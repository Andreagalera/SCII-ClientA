"use strict";
import { Component, OnInit } from "@angular/core";
import { ClienteService } from "../../services/cliente.service";
import { NgForm } from "@angular/forms";
import * as bcu from "bigint-crypto-utils";
import * as bac from "bigint-conversion";
import * as test from "rsa";
import { HexBase64BinaryEncoding } from "crypto";
import { timeout } from 'q';
const sha = require('object-sha');
import * as CryptoJS from 'crypto-js';




declare var M: any;

@Component({
  selector: "app-clientes",
  templateUrl: "./clientes.component.html",
  styleUrls: ["./clientes.component.css"],
  providers: [ClienteService]
})
export class ClientesComponent implements OnInit {
  messageForm: NgForm;
  dataReceive: string;

  publicKey: test.PublicKey;
  publicKeyTTP: test.PublicKey;

  keyPair: test.KeyPair;

  decrypted: string;
  verified: string;
  r: bigint;
  _ONE: BigInt = BigInt(1);
  response: string;

  encriptKey: CryptoKey;

  constructor(private clientService: ClienteService) { }

  async ngOnInit() {

    // Genera key pair de A
    this.keyPair = await test.generateRandomKeys();
    console.log(this.keyPair);

    // Llamar función obtiene public key de B y TTP
    await this.getPublicKey();
    await this.getPublicKeyTTP();

  }

  // Función para obtener la public key de B
  async getPublicKey() {
    this.clientService.getData().subscribe(data => {
      this.publicKey = new test.PublicKey(
        bac.hexToBigint(data.e),
        bac.hexToBigint(data.n)
      );
      this.dataReceive = this.publicKey.n;
    });
  }

  // Función para obtener la public key de TTP
  async getPublicKeyTTP() {
    this.clientService.getPublicKeyTTP().subscribe(data => {
      this.publicKeyTTP = new test.PublicKey(
        bac.hexToBigint(data.e),
        bac.hexToBigint(data.n)
      );
    });
  }

  async postData(form: NgForm) {
    console.log(form.value.name);
    const c = this.publicKey.encrypt(bac.textToBigint(form.value.name));
    const message = { msg: bac.bigintToHex(c) };
    this.clientService.postData(message).subscribe(res => {
      M.toast({ html: "Mensaje enviado" });
      // console.log(message.msg);
      this.decrypted = bac.bigintToText(bac.hexToBigint(res['msg']));
    });
  }

  async sign_message(form: NgForm) {
    const m = bac.bigintToHex(bac.textToBigint(form.value.name));
    const message = {
      msg: m
    };
    this.clientService.post_message_sign(message).subscribe(res => {
      const s = bac.hexToBigint(res['msg']);
      const m = this.publicKey.verify(s);
      console.log(m);
      this.verified = bac.bigintToText(m);
    });
  }

  async blind_sign_message(form: NgForm) {
    // Generate the blinding factor
    const m = bac.textToBigint(form.value.name);
    do {
      this.r = await bcu.prime(bcu.bitLength(this.publicKey.n));
    } while (!(bcu.gcd(this.r, this.publicKey.n) === this._ONE))
    // Generate the blind message
    const b = await bac.bigintToHex(
      (m * this.publicKey.encrypt(this.r)) % this.publicKey.n
    );
    // Criptograma
    // const c = this.encriptKeyFnc(b);
    var ts = new Date();
    const body = {
      type: "1",
      src: "A",
      dest: "B",
      msg: b,
      timestamp: ts
    };
    // Signature
    const digest = await sha.digest(body, 'SHA-256');
    const digestHex = await bac.hexToBigint(digest);
    let signature = this.keyPair.privateKey.sign(digestHex);
    signature = await bac.bigintToHex(signature);
    const message = {
      body: body,
      signature: signature
    };

    this.clientService.post_message_sign(message).subscribe(async res => {
      console.log(res);
      const bs = bac.hexToBigint(res['body']['msg']);
      const s =
        (await (bs * bcu.modInv(this.r, this.publicKey.n))) % this.publicKey.n;
      const m = await this.publicKey.verify(s);
      let m1 = bac.bigintToText(m);
      // console.log(m1);
      document.getElementById(
        "blind-sign-verified"
      ).innerHTML = ("The message verified is: " +
        bac.bigintToText(m));

      // Si el mensaje de B se recibe como que quiere la k
      if (res['body']['type'] == 2) {
        // Llamar a servicio que envie a TTP k
        var tsTTP = new Date();
        const k = 2;
        const body = {
          type: "3",
          src: "A",
          dest: "B",
          ttp: "TTP",
          k: k,
          timestamp: tsTTP
        };
        // Signature
        const digestTTP = await sha.digest(body, 'SHA-256');
        const digestHexTTP = await bac.hexToBigint(digestTTP);
        let signatureTTP = this.keyPair.privateKey.sign(digestHexTTP);
        signatureTTP = await bac.bigintToHex(signatureTTP);
        const messageTTP = {
          body: body,
          signature: signatureTTP
        };

        this.clientService.sendK(messageTTP).subscribe(async resTTP =>{
          console.log("B ya puede saber C");
          console.log(resTTP);
        });


      }
    });
  }


  // Criptograma
  async encriptKeyFnc(data) {
    window.crypto.subtle.importKey(
      "jwk", //can be "jwk" or "raw"
      {   //this is an example jwk key, "raw" would be an ArrayBuffer
        kty: "oct",
        k: "Y0zt37HgOx-BY7SQjYVmrqhPkO44Ii2Jcb9yydUDPfE",
        alg: "A256CBC",
        ext: true,
      },
      {   //this is the algorithm options
        name: "AES-CBC",
        length: 256,
      },
      false, //whether the key is extractable (i.e. can be used in exportKey)
      ["encrypt", "decrypt"] //can be "encrypt", "decrypt", "wrapKey", or "unwrapKey"
    )
      .then(function (key) {
        //returns the symmetric key
        // this.encriptKey = key;
        console.log(key);
        window.crypto.subtle.encrypt(
          {
            name: "AES-CBC",
            //Don't re-use initialization vectors!
            //Always generate a new iv every time your encrypt!
            iv: window.crypto.getRandomValues(new Uint8Array(16)),
          },
          key, //from generateKey or importKey above
          data //ArrayBuffer of data you want to encrypt
        )
          .then(function (encrypted) {
            //returns an ArrayBuffer containing the encrypted data
            console.log(new Uint8Array(encrypted));
            return encrypted;
          })
        // .catch(function (err) {
        //   console.error(err);
        // });
      });
    // return encriptKey;

  }
  // .catch(function (err) {
  //   console.error(err);
  // });


  async encriptK(data, encriptKey) {
    window.crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        //Don't re-use initialization vectors!
        //Always generate a new iv every time your encrypt!
        iv: window.crypto.getRandomValues(new Uint8Array(16)),
      },
      encriptKey, //from generateKey or importKey above
      data //ArrayBuffer of data you want to encrypt
    )
      .then(function (encrypted) {
        //returns an ArrayBuffer containing the encrypted data
        console.log(new Uint8Array(encrypted));
        return encrypted;
      })
    // .catch(function (err) {
    //   console.error(err);
    // });
  }



}
