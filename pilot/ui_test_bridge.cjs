"use strict";
// Disposable loopback browser adapter for RootDirectory UI rehearsal only.
// Production TLS/Origin/Secure-cookie boundaries are tested separately. This
// adapter is not a deployment component and must never target production data.
const http = require("node:http");
const fs = require("node:fs");
if(process.argv[2]!=="--test-only")throw new Error("Explicit --test-only required");
const backend=Number(process.argv[3]),port=Number(process.argv[4]),dropMarker=process.argv[5];
if(!Number.isInteger(backend)||!Number.isInteger(port)||backend<1024||port<1024)throw new Error("Invalid loopback ports");
const allowed=new Set(["localhost:"+port,"127.0.0.1:"+port]);
const server=http.createServer((req,res)=>{
 if(!allowed.has(req.headers.host)){res.writeHead(403);res.end();return;}
 if(!req.url.startsWith("/")||req.url.startsWith("//")){res.writeHead(400);res.end();return;}
 const headers={...req.headers,host:"panel.home.arpa"};
 if(!["GET","HEAD"].includes(req.method)){
  if(req.headers.origin!=="http://"+req.headers.host){res.writeHead(403);res.end();return;}
  headers.origin="https://panel.home.arpa";
 }
 const upstream=http.request({host:"127.0.0.1",port:backend,path:req.url,method:req.method,headers},response=>{
  // One controlled lost acknowledgement, after the real API queued the intent.
  if(response.statusCode===202&&dropMarker&&fs.existsSync(dropMarker)){
   fs.unlinkSync(dropMarker);response.resume();res.destroy();return;
  }
  const output={...response.headers,"x-vpn-control-test-bridge":"loopback-only"};
  // This HTTP fixture never carries production credentials. Preserve HttpOnly/
  // SameSite, while production's Secure flag remains covered by auth tests.
  if(output["set-cookie"])output["set-cookie"]=output["set-cookie"].map(value=>value.replace(/;\s*Secure(?=;|$)/gi,""));
  res.writeHead(response.statusCode,output);response.pipe(res);
 });
 upstream.on("error",()=>{if(!res.headersSent)res.writeHead(502);res.end();});
 req.pipe(upstream);
});
server.listen(port,"127.0.0.1",()=>console.log("UI test bridge listening on loopback only"));
