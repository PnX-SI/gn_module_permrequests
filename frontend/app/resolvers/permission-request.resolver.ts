import { Injectable } from '@angular/core';
import { Resolve, ActivatedRouteSnapshot } from '@angular/router';
import { Observable, throwError } from 'rxjs';

import { PermissionRequestResponse, PermissionRequestService } from '../services/permissionRequest.service';

@Injectable()
export class PermissionRequestResolver implements Resolve<PermissionRequestResponse> {
  constructor(private _permissionRequestService: PermissionRequestService) {}

  resolve(route: ActivatedRouteSnapshot): Observable<PermissionRequestResponse> {
    const idPermissionRequest = Number(route.paramMap.get('id_permission_request'));

    if (Number.isNaN(idPermissionRequest)) {
      return throwError(() => new Error(`Invalid permission request id: ${idPermissionRequest}`));
    }

    return this._permissionRequestService.getPermissionRequest(idPermissionRequest);
  }
}
