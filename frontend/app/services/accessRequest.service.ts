import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ConfigService } from '@geonature/services/config.service';
import { AccessRequest, AccessRequestScope } from '../models/accessRequest';
import { ModuleService } from '@geonature/services/module.service';

export interface AccessRequestListResponse {
  total: number;
  page: number;
  per_page: number;
  items: AccessRequest[];
}

export type AccessRequestResponse = AccessRequest;
export interface AccessRequestPayload {
  description: string | null;
  initialization_date: string | null;
  expiration_date: string;
  id_validator?: number | null;
  scope: AccessRequestScope;
  sensitivity_filter?: boolean;
  taxa: number[];
}

export interface ValidatedPayload {
  validated: boolean | null;
}

@Injectable()
export class AccessRequestService {
  constructor(
    private _http: HttpClient,
    private _config: ConfigService,
    private _moduleService: ModuleService
  ) {}

  getAccessRequests(params: HttpParams): Observable<AccessRequestListResponse> {
    return this._http.get<AccessRequestListResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/`,
      { params: params }
    );
  }
  getAccessRequest(id_access_request: number): Observable<AccessRequestResponse> {
    return this._http.get<AccessRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${id_access_request}`
    );
  }

  private _serializePayload(payload: AccessRequestPayload) {
    const normalizedTaxa = Array.from(
      new Set((payload.taxa ?? []).map((taxonId) => Number(taxonId)))
    ).filter((taxonId) => Number.isFinite(taxonId));
    return {
      ...payload,
      taxa: normalizedTaxa,
    };
  }

  updateAccessRequest(
    accessRequest: AccessRequest,
    payload: AccessRequestPayload
  ): Observable<AccessRequestResponse> {
    payload = this._serializePayload(payload);
    return this._http.patch<AccessRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${accessRequest.id_access_request}`,
      payload
    );
  }

  createAccessRequest(payload: AccessRequestPayload): Observable<AccessRequestResponse> {
    payload = this._serializePayload(payload);
    return this._http.post<AccessRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/`,
      payload
    );
  }

  deleteAccessRequest(accessRequest: AccessRequest): Observable<void> {
    return this._http.delete<void>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${accessRequest.id_access_request}`
    );
  }

  updateValidated(
    id_access_request: number,
    payload: ValidatedPayload
  ): Observable<AccessRequestResponse> {
    return this._http.patch<AccessRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${id_access_request}/validated`,
      payload
    );
  }
}
