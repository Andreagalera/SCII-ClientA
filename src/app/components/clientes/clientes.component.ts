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
const toBuffer = require('typedarray-to-buffer')





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

  key: string;
  c: string;
  cryptoKey;
  algKeyGen;
  algEncrypt;
  keyUsages;

  Pr;
  Pkp;

  constructor(private clientService: ClienteService) {

    // No repudiation
    this.algKeyGen = {
      name: 'AES-CBC',
      length: 256
    };
    this.algEncrypt = {
      name: 'AES-CBC',
      iv: null
    };
    this.keyUsages = [
      'encrypt',
      'decrypt'
    ];
  }

  async ngOnInit() {

    // Genera key pair de A
    this.keyPair = await test.generateRandomKeys();
    console.log(this.keyPair);

    // Llamar función obtiene public key de B y TTP
    await this.getPublicKey();
    await this.getPublicKeyTTP();

    // No repudiation
    await crypto.subtle.generateKey(this.algKeyGen,true,this.keyUsages)
      .then(data => this.cryptoKey = data);
    await crypto.subtle.exportKey("raw",this.cryptoKey)
      .then(data => this.key = bac.bufToHex(data));

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
    // const digest = await sha.digest(b, 'SHA-256');
    const message = {
      msg: b
    };
    // const digest = await sha.digest(message, 'SHA-256');
    this.clientService.post_message_sign(message).subscribe(async res => {
      const bs = bac.hexToBigint(res['msg']);
      const s =
        (await (bs * bcu.modInv(this.r, this.publicKey.n))) % this.publicKey.n;
      const m = await this.publicKey.verify(s);
      let m1= bac.bigintToText(m);
      console.log(m1);
      document.getElementById(
        "blind-sign-verified"
      ).innerHTML = ("The message verified is: " +
        bac.bigintToText(m));
    });
  }

  async noRepudation(form: NgForm) {
    const m = form.value.name;
    await this.encrypt(m);
    const mBigint = await bac.textToBigint(m);
    const mHex = await bac.bigintToHex(mBigint);

    console.log(this.c);
    var ts = new Date();
    const body = {
      type: "1",
      src: "A",
      dest: "B",
      msg: this.c,
      timestamp: ts
    };
    // Signature
    const digest = await sha.digest(body, 'SHA-256');
    const digestHex = await bac.hexToBigint(digest);
    let signature = this.keyPair.privateKey.sign(digestHex);
    signature = await bac.bigintToHex(signature);
    const message = {
      body: body,
      signature: signature,
      pubKey: {e: bac.bigintToHex(this.keyPair.publicKey.e), n: bac.bigintToHex(this.keyPair.publicKey.n)}
    };

    this.clientService.no_repudation(message).subscribe(async res => {
      console.log(res);
       // Comprovar prueba
      let proofDigest = bac.bigintToHex (await this.publicKey.verify(bac.hexToBigint(res['signature'])));
      let bodyDigest = await sha.digest(res['body']);
      // Comprovar timestamp
      var tsTTP = new Date();
      var tsB = res['body']['timestamp'];
      tsB = new Date(tsB);
      var seconds = (tsTTP.getTime() - tsB.getTime()) / 1000;
      // Si el mensaje de B se recibe como que quiere la k
      if ((res['body']['type'] == 2) && (seconds < 1) && (bodyDigest === proofDigest)) {
        this.Pr = res['signature'];
        // Llamar a servicio que envie a TTP k
        // var tsTTP = new Date();
        console.log(this.cryptoKey);
        console.log(this.algEncrypt.iv);
        console.log(bac.bufToHex(this.algEncrypt.iv));
        console.log(this.key);
        // const k = 2;
        const body = {
          type: "3",
          src: "A",
          dest: "B",
          ttp: "TTP",
          k: this.key,
          iv: bac.bufToHex(this.algEncrypt.iv),
          timestamp: tsTTP
        };
        // Signature
        const digestTTP = await sha.digest(body, 'SHA-256');
        const digestHexTTP = await bac.hexToBigint(digestTTP);
        let signatureTTP = this.keyPair.privateKey.sign(digestHexTTP);
        signatureTTP = await bac.bigintToHex(signatureTTP);
        const messageTTP = {
          body: body,
          signature: signatureTTP,
          pubKey: {e: bac.bigintToHex(this.keyPair.publicKey.e), n: bac.bigintToHex(this.keyPair.publicKey.n)}
        };

        this.clientService.sendK(messageTTP).subscribe(async resTTP =>{
          console.log(resTTP);
          // Comprovar prueba
          let proofDigest2 = bac.bigintToHex (await this.publicKeyTTP.verify(bac.hexToBigint(resTTP['signature'])));
          let bodyDigest2 = await sha.digest(resTTP['body']);
          // Comprovar timestamp
          var tsTTP3 = new Date();
          var tsTTP2 = res['body']['timestamp'];
          tsTTP2 = new Date(tsTTP2);
          var seconds2 = (tsTTP3.getTime() - tsTTP2.getTime()) / 1000;
          // Si el mensaje de B se recibe como que quiere la k
          if ((resTTP['body']['type'] == 4) && (seconds2 < 1) && (bodyDigest2 === proofDigest2)) {
          console.log("B ya puede saber C");
          this.Pkp = resTTP['signature'];
          }
          else { console.log("Pruebas malamente 2"); }
        });


      }
      else { console.log("Pruebas malamente"); }

    });
  }

  async encrypt(message) {
    this.algEncrypt.iv = await crypto.getRandomValues(new Uint8Array(16));
    await crypto.subtle.encrypt(this.algEncrypt, this.cryptoKey, bac.textToBuf(message))
      .then(data => this.c = bac.bufToHex(data));
  }

  async decrypt(message) {
    await crypto.subtle.decrypt(this.algEncrypt, this.cryptoKey, bac.textToBuf(message))
      .then(data => this.c = bac.bufToHex(data));
  }


}
