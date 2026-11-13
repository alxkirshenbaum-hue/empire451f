package storage

import (
 "bytes"
 "encoding/json"
 "os"
"os/exec"
"strings"
 "testing"
)

func TestRoutingOptionsAndImmutableVariants(t *testing.T){
 _,r,created:=mutationFixture(t)
 body,err:=os.ReadFile("../../../templates/sfa-profile.json");if err!=nil{t.Fatal(err)}
 // Fixture approval is explicit; existing bindings and credentials stay intact.
 if _,err=r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?",string(body),digest(body));err!=nil{t.Fatal(err)}
 variants,err:=r.InstallRoutingVariants(ctx,request.TemplateRevisionID,digest(body));if err!=nil{t.Fatal(err)}
 replay,err:=r.InstallRoutingVariants(ctx,request.TemplateRevisionID,digest(body));if err!=nil||replay["base"]!=variants["base"]||replay["ru_download_manager"]!=variants["ru_download_manager"]{t.Fatal("variant replay",err)}
 old,err:=r.OpenForPurpose(ctx,created.UserID,RenderProfile);if err!=nil{t.Fatal(err)};defer clear(old)
 var baseline []byte
 for _,client:=range []string{Client1144,ClientAlpha13}{
  blob,err:=r.RenderProfile(ctx,created.UserID,"vpn.example.org",ProfileOptions{Client:client});if err!=nil{t.Fatal(client,err)}
  defer clear(blob)
  if bytes.Contains(blob,[]byte("package_name"))||bytes.Contains(blob,[]byte("geosite-ru"))||bytes.Contains(blob,[]byte(".xn--p1ai")){t.Fatal("base contains RU/DM")}
  if !bytes.Contains(blob,[]byte("panel.home.arpa")){t.Fatal("lost panel route")}
  if baseline==nil{baseline=bytes.Clone(blob);defer clear(baseline)}else if !bytes.Equal(baseline,blob){t.Fatal("base render diverged between clients")}
 }
 for _,options:=range []ProfileOptions{
  {Client:Client1144,RUDM:true,Acknowledge:true},
  {Client:ClientAlpha13,RUDM:true},
  {Client:"sfa-1.15-alpha3",RUDM:true,Acknowledge:true},
  {Client:"sfa-1.15"},
 }{
  if blob,err:=r.RenderProfile(ctx,created.UserID,"vpn.example.org",options);err!=ErrTemplateIncompatible||blob!=nil{t.Fatal("unsupported options accepted",err)}
 }
 blob,err:=r.RenderProfile(ctx,created.UserID,"vpn.example.org",ProfileOptions{Client:ClientAlpha13,RUDM:true,Acknowledge:true});if err!=nil{t.Fatal(err)};defer clear(blob)
 if !bytes.Contains(blob,[]byte("package_name"))||!bytes.Contains(blob,[]byte("geosite-ru")){t.Fatal("optional policy missing")}
 var got map[string]any
 if json.Unmarshal(blob,&got)!=nil{t.Fatal("invalid optional JSON")}
 after,err:=r.OpenForPurpose(ctx,created.UserID,RenderProfile);if err!=nil||!bytes.Equal(after,old){t.Fatal("option rotated credential",err)};clear(after)
 var saved string
 if err=r.db.QueryRow("SELECT body_json FROM template_revisions WHERE id=?",request.TemplateRevisionID).Scan(&saved);err!=nil||saved!=string(body){t.Fatal("edited source revision",err)}
}

func TestProfileCheckerMatrix(t *testing.T){
 _,r,created:=mutationFixture(t)
 source,err:=os.ReadFile("../../../templates/sfa-profile.json");if err!=nil{t.Fatal(err)}
 if _,err=r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?",string(source),digest(source));err!=nil{t.Fatal(err)}
 if _,err=r.InstallRoutingVariants(ctx,request.TemplateRevisionID,digest(source));err!=nil{t.Fatal(err)}
 for _,tc:=range []struct{name,env,version string;options ProfileOptions}{
  {"base1144","VPN_TEST_SFA_CHECK_1144","1.14.4",ProfileOptions{Client:Client1144}},
  {"baseAlpha13","VPN_TEST_SFA_CHECK_ALPHA13","1.15.0-alpha.13",ProfileOptions{Client:ClientAlpha13}},
  {"optionalAlpha13","VPN_TEST_SFA_CHECK_ALPHA13","1.15.0-alpha.13",ProfileOptions{Client:ClientAlpha13,RUDM:true,Acknowledge:true}},
 }{
  t.Run(tc.name,func(t *testing.T){
   binary:=os.Getenv(tc.env);if binary==""{t.Skip("exact-version checker not configured")}
   version,err:=exec.Command(binary,"version").Output();if err!=nil||strings.Split(strings.TrimSpace(string(version)),"\n")[0]!="sing-box version "+tc.version{t.Fatal("wrong checker version",err)}
   blob,err:=r.RenderProfile(ctx,created.UserID,"vpn.example.org",tc.options);if err!=nil{t.Fatal(err)};defer clear(blob)
   command:=exec.Command(binary,"check","-c","/dev/stdin");command.Stdin=bytes.NewReader(blob);command.Dir=t.TempDir()
   if err=command.Run();err!=nil{t.Fatal("exact-version profile check failed",err)}
  })
 }
}
