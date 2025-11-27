import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ConfigService } from '@geonature/services/config.service';
import { PermissionRequest, PermissionRequestScope } from '../models/permissionRequest';
import { ModuleService } from '@geonature/services/module.service';

export interface PermissionRequestListResponse {
  total: number;
  page: number;
  per_page: number;
  items: PermissionRequest[];
}

export type PermissionRequestResponse = PermissionRequest;
export interface PermissionRequestPayload {
  description: string | null;
  initialization_date: string | null;
  expiration_date: string;
  id_validator?: number | null;
  scope: PermissionRequestScope;
  sensitivity_filter?: boolean;
  taxa: number[];
  areas: number[];
}

export interface ValidatedPayload {
  validated: boolean | null;
  validation_description?: string | null;
}

@Injectable()
export class PermissionRequestService {
  constructor(
    private _http: HttpClient,
    private _config: ConfigService,
    private _moduleService: ModuleService
  ) {}

  getPermissionRequests(params: HttpParams): Observable<PermissionRequestListResponse> {
    return this._http.get<PermissionRequestListResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/`,
      { params: params }
    );
  }
  getPermissionRequest(id_permission_request: number): Observable<PermissionRequestResponse> {
    return this._http.get<PermissionRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${id_permission_request}`
    );
  }

  private _serializePayload(payload: PermissionRequestPayload) {
    const normalizedTaxa = Array.from(
      new Set((payload.taxa ?? []).map((taxonId) => Number(taxonId)))
    ).filter((taxonId) => Number.isFinite(taxonId));
    const normalizedAreas = Array.from(
      new Set((payload.areas ?? []).map((areaId) => Number(areaId)))
    ).filter((areaId) => Number.isFinite(areaId));
    return {
      ...payload,
      taxa: normalizedTaxa,
      areas: normalizedAreas,
    };
  }

  updatePermissionRequest(
    permissionRequest: PermissionRequest,
    payload: PermissionRequestPayload
  ): Observable<PermissionRequestResponse> {
    payload = this._serializePayload(payload);
    return this._http.patch<PermissionRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${permissionRequest.id_permission_request}`,
      payload
    );
  }

  createPermissionRequest(payload: PermissionRequestPayload): Observable<PermissionRequestResponse> {
    payload = this._serializePayload(payload);
    return this._http.post<PermissionRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/`,
      payload
    );
  }

  deletePermissionRequest(permissionRequest: PermissionRequest): Observable<void> {
    return this._http.delete<void>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${permissionRequest.id_permission_request}`
    );
  }

  updateValidated(
    id_permission_request: number,
    payload: ValidatedPayload
  ): Observable<PermissionRequestResponse> {
    return this._http.patch<PermissionRequestResponse>(
      `${this._config.API_ENDPOINT}/${this._moduleService.currentModule.module_url}/${id_permission_request}/validated`,
      payload
    );
  }
}
