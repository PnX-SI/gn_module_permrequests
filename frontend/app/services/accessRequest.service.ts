import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ConfigService } from '@geonature/services/config.service';
import { AccessRequest } from '../models/accessRequest';

export interface AccessRequestListResponse {
  total: number;
  page: number;
  per_page: number;
  items: AccessRequest[];
}

export type AccessRequestReponse = AccessRequest;
export interface AccessRequestPayload {
  description: string | null;
  initialization_date: string | null;
  expiration_date: string;
  id_validator?: number | null;
}

@Injectable()
export class AccessRequestService {
  constructor(
    private _http: HttpClient,
    private _config: ConfigService
  ) {}

  getAccessRequests(params: HttpParams): Observable<AccessRequestListResponse> {
    return this._http.get<AccessRequestListResponse>(
      `${this._config.API_ENDPOINT}/access_request/`,
      { params: params }
    );
  }
  getAccessRequest(id_access_request: number): Observable<AccessRequestReponse> {
    return this._http.get<AccessRequestReponse>(
      `${this._config.API_ENDPOINT}/access_request/${id_access_request}`
    );
  }

  private _serializePayload(payload: AccessRequestPayload){
    return payload;
  }

  updateAccessRequest(
    accessRequest: AccessRequest,
    payload: AccessRequestPayload
  ): Observable<AccessRequestReponse> {
    payload = this._serializePayload(payload);
    return this._http.patch<AccessRequestReponse>(
      `${this._config.API_ENDPOINT}/access_request/${accessRequest.id_access_request}`,
      payload
    );
  }

  createAccessRequest(payload: AccessRequestPayload): Observable<AccessRequestReponse> {
    payload = this._serializePayload(payload);
    return this._http.post<AccessRequestReponse>(
      `${this._config.API_ENDPOINT}/access_request/`,
      payload
    );
  }

  deleteAccessRequest(accessRequest: AccessRequest): Observable<void> {
    return this._http.delete<void>(
      `${this._config.API_ENDPOINT}/access_request/${accessRequest.id_access_request}`
    );
  }
}
