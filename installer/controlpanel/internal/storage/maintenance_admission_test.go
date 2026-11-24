package storage

import (
 "errors"
 "sync"
 "testing"
)

func TestMaintenanceBlocksCanonicalAdmissions(t *testing.T) {
 for _,action:=range []string{"create","owned-create","rename","disable","rotate"} {t.Run(action,func(t *testing.T){
  _,r,u:=mutationFixture(t);if e:=r.ConfigureBackups(ctx,"test-key");e!=nil{t.Fatal(e)}
  j,e:=r.QueueMaintenance(ctx,"mutation-run","owner",id(),MaintenanceRequest{Action:"backup.create"});if e!=nil{t.Fatal(e)}
  var rejected error
  switch action {case "create":q:=request;q.Login="new-after-maintenance";_,rejected=r.QueueCreate(ctx,"owner",id(),q)
  case "owned-create":_,rejected=r.QueueOwnedCreate(ctx,"mutation-run","owner",id(),"new-after-maintenance")
  case "rename":_,rejected=r.QueueOwnedRename(ctx,"mutation-run","owner",id(),u.UserID,2,"Changed")
  default:_,rejected=r.QueueOwnedMutation(ctx,"mutation-run","owner",id(),MutationRequest{UserID:u.UserID,Action:action,ExpectedVersion:2,Reason:"test"})}
  if !errors.Is(rejected,ErrOperationInProgress){t.Fatalf("admitted %s: %v",action,rejected)}
  if e=r.CancelMaintenance(ctx,"owner",j.OperationID);e!=nil{t.Fatal(e)}
 })}
}

func TestMaintenanceConcurrentAdmissionSeparateConnections(t *testing.T) {
 path,r,u:=mutationFixture(t);if e:=r.ConfigureBackups(ctx,"test-key");e!=nil{t.Fatal(e)};other:=openTest(t,path)
 start:=make(chan struct{});result:=make(chan error,2);var wg sync.WaitGroup;wg.Add(2)
 go func(){defer wg.Done();<-start;_,e:=r.QueueMaintenance(ctx,"mutation-run","owner",id(),MaintenanceRequest{Action:"backup.create"});result<-e}()
 go func(){defer wg.Done();<-start;_,e:=other.QueueOwnedMutation(ctx,"mutation-run","owner",id(),MutationRequest{UserID:u.UserID,Action:"disable",ExpectedVersion:2,Reason:"test"});result<-e}()
 close(start);wg.Wait();close(result);accepted,blocked:=0,0;for e:=range result{if e==nil{accepted++}else if errors.Is(e,ErrOperationInProgress){blocked++}else{t.Fatal(e)}}
 if accepted!=1||blocked!=1{t.Fatalf("accepted=%d blocked=%d",accepted,blocked)}
}
