import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ConfigService } from '@geonature/services/config.service';
import { DEFAULT_PAGINATION, PaginationItem } from '../models/paginationItem';
import { AccessRequestSummary } from '../models/accessRequestSummary';

export interface AccessRequestListResponse {
  total: number;
  page: number;
  per_page: number;
  items: AccessRequestSummary[];
}

export interface AccessRequestReponse extends AccessRequestSummary {}

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
}
