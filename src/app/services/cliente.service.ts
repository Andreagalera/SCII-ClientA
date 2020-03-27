import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import {Observable} from 'rxjs';
import * as test from 'rsa';


@Injectable({
  providedIn: 'root'
})
export class ClienteService {
  nombre: string;
  readonly URL_API = 'http://localhost:3000/api/clientes';

  constructor(private http: HttpClient) { }

  getData(): Observable<test.PublicKey> {
    return this.http.get<test.PublicKey>(this.URL_API);
  }

  postData(body: object) {
    return this.http.post(this.URL_API, body);
  }

  post_message_sign(body: object) {
    return this.http.post(this.URL_API + '/sign', body);
  }

}
