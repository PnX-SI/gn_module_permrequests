import { Injectable } from '@angular/core';
import { Resolve, ActivatedRouteSnapshot } from '@angular/router';
import { Observable, throwError } from 'rxjs';

import { AccessRequestResponse, AccessRequestService } from '../services/accessRequest.service';

@Injectable()
export class AccessRequestResolver implements Resolve<AccessRequestResponse> {
  constructor(private _accessRequestService: AccessRequestService) {}

  resolve(route: ActivatedRouteSnapshot): Observable<AccessRequestResponse> {
    const idAccessRequest = Number(route.paramMap.get('id_access_request'));

    if (Number.isNaN(idAccessRequest)) {
      return throwError(() => new Error(`Invalid access request id: ${idAccessRequest}`));
    }

    return this._accessRequestService.getAccessRequest(idAccessRequest);
  }
}
