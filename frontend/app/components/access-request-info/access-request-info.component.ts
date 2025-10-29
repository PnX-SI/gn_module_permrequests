import { Component, Input, OnDestroy, OnInit, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';

import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { AccessRequest, AccessRequestScope, DEFAULT_SCOPE } from '../../models/accessRequest';

@Component({
  standalone: true,
  selector: 'access-request-info',
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
  imports: [CommonModule],
})
export class AccessRequestInfoComponent {
  @Input()
  public accessRequest: AccessRequest | null = null;

  readonly scopeLabels: Record<AccessRequestScope, string> = {
    [AccessRequestScope.USER]: 'Utilisateur',
    [AccessRequestScope.ORGANISM]: 'Organisme',
  };

  getScopeLabel(scope: AccessRequestScope | null): string {
    if (!scope) {
      return this.scopeLabels[DEFAULT_SCOPE];
    }
    if (scope in this.scopeLabels) {
      return this.scopeLabels[scope as AccessRequestScope];
    }
    return scope;
  }
}
