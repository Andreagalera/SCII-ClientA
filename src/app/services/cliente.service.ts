import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {Observable} from 'rxjs';
import * as test from 'rsa';


@Injectable({
  providedIn: 'root'
})
export class ClienteService {
  nombre: string;
  readonly URL_APIB = 'http://localhost:3000/api/clientes';
  readonly URL_APITTP = 'http://localhost:3001/api/clientes';


  constructor(private http: HttpClient) { }

  getData(): Observable<test.PublicKey> {
    return this.http.get<test.PublicKey>(this.URL_APIB);
  }

  getPublicKeyTTP(): Observable<test.PublicKey> {
    return this.http.get<test.PublicKey>(this.URL_APITTP + '/publicKeyTTP');
  }

  postData(body: object) {
    return this.http.post(this.URL_APIB, body);
  }

  post_message_sign(body: object) {
    return this.http.post(this.URL_APIB + '/sign', body);
  }

  sendK(body: object) {
    return this.http.post(this.URL_APITTP + '/msg3', body);
  }

}
