package storage

import (
 "bytes"
 "context"
 "errors"
 "os"
 "testing"
 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestVaultRotationCopyPreservesCredentialsAndSource(t *testing.T){
 path,r,u:=snapshotFixture(t);before,e:=r.OpenForPurpose(ctx,u.UserID,RenderProfile);if e!=nil{t.Fatal(e)};defer clear(before)
 next,_:=vault.New(bytes.Repeat([]byte{92},32));stage:=t.TempDir();os.Chmod(stage,0700)
 captured,e:=r.RotateVaultCopy(ctx,stage,"",next);if e!=nil{t.Fatal(e)}
 rotated,e:=Open(ctx,captured.Path,next,2);if e!=nil{t.Fatal(e)};defer rotated.Close()
 after,e:=rotated.OpenForPurpose(ctx,u.UserID,RenderProfile);if e!=nil||!bytes.Equal(before,after){t.Fatal("credential changed",e)};clear(after)
 if _,e=Open(ctx,captured.Path,r.vault,2);!errors.Is(e,ErrVaultKey){t.Fatal("old key accepted by candidate",e)}
 if _,e=Open(ctx,path,next,1);!errors.Is(e,ErrVaultKey){t.Fatal("new key accepted by source",e)}
 source,e:=r.OpenForPurpose(ctx,u.UserID,RenderProfile);if e!=nil||!bytes.Equal(source,before){t.Fatal("source changed",e)};clear(source)
 if _,e=r.InspectSnapshot(ctx,"");e!=nil{t.Fatal(e)}
}
func TestVaultRotationCopyCancellationCleansOnlyCandidate(t *testing.T){
 _,r,_:=snapshotFixture(t);stage:=t.TempDir();os.Chmod(stage,0700);sentry:=stage+"/sentry";os.WriteFile(sentry,[]byte("keep"),0600);next,_:=vault.New(bytes.Repeat([]byte{93},32));c,cancel:=context.WithCancel(ctx);cancel()
 if _,e:=r.RotateVaultCopy(c,stage,"",next);!errors.Is(e,context.Canceled){t.Fatal(e)};entries,_:=os.ReadDir(stage);if len(entries)!=1||entries[0].Name()!="sentry"{t.Fatal("unexpected cleanup")}
}
