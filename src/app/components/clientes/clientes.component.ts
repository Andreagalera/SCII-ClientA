"use strict";
import { Component, OnInit } from "@angular/core";
import { ClienteService } from "../../services/cliente.service";
import { NgForm } from "@angular/forms";
import * as bcu from "bigint-crypto-utils";
import * as bac from "bigint-conversion";
import * as test from "rsa";
import {HexBase64BinaryEncoding} from "crypto";
const sha = require('object-sha');

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
  keyPair: test.KeyPair;

  decrypted: string;
  verified: string;
  r: bigint;
  _ONE: BigInt = BigInt(1);
  response: string;

  constructor(private clientService: ClienteService) {}

  async ngOnInit() {
    // this.getPublicKey();

    this.keyPair = await test.generateRandomKeys();
    console.log(this.keyPair);
    await this.getPublicKey();
  }

  async getPublicKey() {
    this.clientService.getData().subscribe(data => {
      this.publicKey = new test.PublicKey(
        bac.hexToBigint(data.e),
        bac.hexToBigint(data.n)
      );
      this.dataReceive = this.publicKey.n;
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



}
