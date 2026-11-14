//go:build linux

package main

import (
 "context"
 "encoding/json"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

// This command authenticates off-node and checks a NEW private staging copy.
// Its report deliberately cannot promote a registry backup to verified.
func offlineVerify(args []string,out,stderr io.Writer) int {
 f:=flag.NewFlagSet("backup offline-verify",flag.ContinueOnError);f.SetOutput(io.Discard)
 envelope:=f.String("envelope","","Encrypted envelope")
 private:=f.String("private-key","","Off-node recipient key file")
 cipherHash:=f.String("cipher-sha256","","Authenticated receipt digest")
 manifestHash:=f.String("manifest-sha256","","Authenticated manifest digest")
 owner:=f.String("owner-run","","Expected owner run")
 own:=f.String("own-operation","","Captured backup operation")
 stage:=f.String("staging","","New private output directory")
 helper:=f.String("helper","","Trusted backup_artifact.py")
 panel:=f.String("source-panel-root","","Trusted source panel root")
 state:=f.String("source-state-root","","Trusted source state root")
 config:=f.String("source-config-root","","Trusted source config root")
 if f.Parse(args)!=nil||f.NArg()!=0||!validCipherDigest(*cipherHash)||!validCipherDigest(*manifestHash)||!status.ValidID(*owner)||(*own!=""&&!status.ValidID(*own))||!filepath.IsAbs(*helper)||!filepath.IsAbs(*private)||!filepath.IsAbs(*envelope)||!filepath.IsAbs(*stage)||!(RestoreSourceRoots{*panel,*state,*config}).valid(){fmt.Fprintln(stderr,"Expected authenticated receipt, trusted source roots and private recovery paths");return 2}
 // A fresh private sibling keeps decrypted plaintext out of argv and reports.
 parent:=filepath.Dir(*stage);resolved,e:=filepath.EvalSymlinks(parent);i,se:=os.Stat(parent)
 if e!=nil||se!=nil||resolved!=parent||!i.IsDir()||i.Mode().Perm()&0077!=0 {fmt.Fprintln(stderr,"Private recovery parent required");return 4}
 temp,e:=os.MkdirTemp(parent,".offline-decrypt-");if e!=nil{return 4};defer os.RemoveAll(temp)
 plain:=filepath.Join(temp,"archive.tar")
 if _,e=artifactCommand(context.Background(),*helper,map[string]string{"action":"decrypt","envelope":*envelope,"private_key_path":*private,"output":plain,"expected_sha256":*cipherHash});e!=nil{fmt.Fprintln(stderr,"Envelope authentication failed");return 4}
 result,e:=verifyManagedArchive(context.Background(),plain,*stage,*manifestHash,*owner,*own,RestoreSourceRoots{*panel,*state,*config})
 if e!=nil{fmt.Fprintln(stderr,"Archive consistency verification failed");return 4}
 report:=struct{Outcome string `json:"outcome"`;ManifestSHA256 string `json:"manifest_sha256"`;Inspection storage.SnapshotInspection `json:"inspection"`;UsableRestore string `json:"usable_restore"`}{"artifact_check_passed",result.ManifestSHA256,result.Inspection,"not_run"}
 if json.NewEncoder(out).Encode(report)!=nil{return 9};return 0
}
