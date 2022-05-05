let msgBox,
	privateKeyBox,
	publicKeyBox,
	publicKeyTestBox,
	encodedMsgBox,
	signBox,
	genKeyBtn,
	verifyBtn,
	chatBox;

/***********************************************************************/
let users = [];
/***********************************************************************/

let privateKey = null;

const hashType = "SHA-256";

const signAlgName = "RSA-PSS";

const signAlg = {
	genKey: {
		name: signAlgName,
		// Consider using a 4096-bit key for systems that require long-term security
		modulusLength: 2048,
		publicExponent: new Uint8Array([1, 0, 1]),
		hash: hashType,
	},
	importKey: {
		name: signAlgName,
		hash: hashType,
	},
	singVerify: {
		name: signAlgName,
		saltLength: 32,
	}
};

const encryptAlgName = "RSA-OAEP";

const encryptAlg = {
	genKey: {
		name: encryptAlgName,
		// Consider using a 4096-bit key for systems that require long-term security
		modulusLength: 4096,
		publicExponent: new Uint8Array([1, 0, 1]),
		hash: hashType,
	},
	importKey: {
		name: encryptAlgName,
		hash: hashType,
	},
	encryptDecrypt: {
		name: encryptAlgName,
	}
};

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8");

/***********************************************************************/

let verifyMsg = async (encMsgHex, key64, signHex) =>
{
	return await importRsaKey(key64, signAlg.importKey).then(async (key) =>
     {
		 const sign = hexToHash(signHex);
		 const encMsg = hexToHash(encMsgHex);

         return await crypto.subtle.verify(
	         signAlg.singVerify,
	         key,
             sign,
             encMsg
         );
     });
};

let encodeAndSign = (msg) =>
{
	crypto.subtle.digest(hashType, encoder.encode(msg)).then( (encodedMsg) =>
    {
	    encodedMsgBox.value = hashToHex(encodedMsg);

        crypto.subtle.sign(
            signAlg.singVerify,
            privateKey,
            encodedMsg
        ).then((signature) =>
        {
	        signBox.value = hashToHex(signature);
        });
    });
};

let genKeys = () =>
{
	crypto.subtle.generateKey(
		signAlg.genKey,
		true,
		["sign", "verify"]
	).then(async (keyPair) =>
	{
		privateKey = keyPair.privateKey;

		crypto.subtle.exportKey("pkcs8", privateKey).then((key) => {
			 privateKeyBox.value = toBase64(key);
		});

		crypto.subtle.exportKey("spki", keyPair.publicKey).then((key) => {
			publicKeyTestBox.value = publicKeyBox.value =  toBase64(key);
		});
	}).then( () =>
    {
        encodeAndSign(msgBox.value);
    });
};

let importRsaKey = async (key64, alg, usages = null, extractable = true) =>
{
	usages = usages || ["verify"];

	return await crypto.subtle.importKey(
		"spki",
		base64ToArr(key64),
		alg,
		extractable,
		usages
	);
};

/**********Helpers************************************/

let hashToHex = (hash) =>
{
	let hashArray = Array.from(new Uint8Array(hash)) // convert buffer to byte array

	return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

let hexToHash = (hexStr) =>
{
	const arr = new Uint8Array(hexStr.match(/[\da-f]{2}/gi).map( (h) => parseInt(h, 16) ));
	return arr.buffer;
};

let toBase64 = (arr) =>
{
	const bufferedArr = String.fromCharCode.apply(null, new Uint8Array(arr));

	return btoa(bufferedArr);
};

let base64ToArr = (str) =>
{
	// base64 decode the string to get the binary data
	const binaryDerString = atob(str);
	// convert from a binary string to an ArrayBuffer
	return str2ab(binaryDerString);
};

let str2ab = (str) =>
{
	const buf = new ArrayBuffer(str.length);
	const bufView = new Uint8Array(buf);
	for (let i = 0, strLen = str.length; i < strLen; i++)
	{
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
};

let initContent = function ()
{
	msgBox = document.getElementById('msgBox');

	privateKeyBox = document.getElementById('privateKeyBox');
	publicKeyBox = document.getElementById('publicKeyBox');
	publicKeyTestBox = document.getElementById('publicKeyTestBox');

	encodedMsgBox = document.getElementById('encodedMsgBox');
	signBox = document.getElementById('signBox');

	genKeyBtn = document.getElementById('genKeyBtn');
	verifyBtn = document.getElementById('verifyBtn');

	chatBox = document.getElementById('chatBox');
}

let initEvents = function ()
{
	msgBox.onchange = function()
	{
		encodeAndSign(this.value);
	};

	genKeyBtn.onclick = function ()
	{
		genKeys();
	};

	verifyBtn.onclick = async function ()
	{
		this.style.color = "black";

		verifyMsg(encodedMsgBox.value, publicKeyTestBox.value, signBox.value).then((result) =>
		                                                                           {
			                                                                           this.style.color = result ? "green" : "red";
		                                                                           });
	};
}

let initUsers = function ()
{
	const usersCnt = 2;
	for(let userID = 0; userID < usersCnt; userID++)
	{
		let user = {
			name: document.getElementById('userName' + userID).innerText,
			msgBox: document.getElementById('msgBox' + userID),
			sendBtn: document.getElementById('sendBtn' + userID),
			keyBox: document.getElementById('keyBox' + userID),
			genKeyBtn: document.getElementById('genKeyBtn' + userID),
			userID: userID,
			privateKey: null,
			publicKey: null
		};

		user.genKeyBtn.onclick = function()
		{
			genUserKey(userID);
		};

		user.sendBtn.onclick = function()
		{
			sendMsgToUser(user.msgBox.value, userID, usersCnt - 1 - userID);
		};

		users.push(user);

		genUserKey(userID);
	}

	console.log(users);
};

let receiveMsgFromUser = function(encryptedMsg64, fromUserID, toUserID)
{
	encryptedMsg64 = encryptedMsg64.trim();
	let fromUser = users[fromUserID];
	let toUser = users[toUserID];
	if(!encryptedMsg64 || !fromUser || !toUser)
		return;

	crypto.subtle.decrypt(encryptAlg.encryptDecrypt, toUser.privateKey, base64ToArr(encryptedMsg64))
		.then((msg) => {
			addMsgToChat(fromUser.name, decoder.decode(msg));
			fromUser.msgBox.value = "";
		})
		.catch(() => {
			alert("Decrypting error!");
		});
};

let addMsgToChat = function(from, msg)
{
	chatBox.innerHTML += `<b>${from}</b>: ${msg}<br/>`;
};


let sendMsgToUser = function(msg, fromUserID, toUserID)
{
	msg = msg.trim();
	let fromUser = users[fromUserID];
	let toUser = users[toUserID];
	if(!msg || !fromUser || !toUser)
		return;

	importRsaKey(toUser.keyBox.value, encryptAlg.importKey, ["encrypt"]).then( (toUserPublicKey) =>
	{
		crypto.subtle.encrypt(encryptAlg.encryptDecrypt, toUserPublicKey, encoder.encode(msg)).then( (encryptedData) =>
		{
			receiveMsgFromUser(toBase64(encryptedData), fromUserID, toUserID);
		});
	});

};

let genUserKey = function(userID)
{
	if (!users[userID])
		return;

	users[userID].sendBtn.disabled = true;

	crypto.subtle.generateKey(
		encryptAlg.genKey,
		true,
		["encrypt", "decrypt"]
	).then(async (keyPair) =>
	       {
			   users[userID].privateKey = keyPair.privateKey;
			   users[userID].publicKey = keyPair.publicKey;

		       crypto.subtle.exportKey("spki", keyPair.publicKey).then((key) =>
		       {
			       users[userID].keyBox.value =  toBase64(key);
			       users[userID].sendBtn.disabled = false;
		       });
	       });
};

document.addEventListener('DOMContentLoaded', function()
{
	initContent();
	initEvents();
	initUsers();


	genKeys();
});