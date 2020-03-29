import { Component, OnInit } from '@angular/core';
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


@Component({
  selector: 'app-norepudation',
  templateUrl: './norepudation.component.html',
  styleUrls: ['./norepudation.component.css'],
  providers: [ClienteService]

})
export class NorepudationComponent implements OnInit {


  constructor(private clientService: ClienteService) { }

  ngOnInit() {

  }

}
