import { Component, Input, OnDestroy, OnInit, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';

import { PermissionRequest, PermissionRequestScope, DEFAULT_SCOPE } from '../../models/permissionRequest';

import { STATUS_COLORS, STATUS_LABELS } from '../../models/status'

@Component({
  standalone: true,
  selector: 'permission-request-info',
  templateUrl: 'permission-request-info.component.html',
  styleUrls: ['./permission-request-info.component.scss'],
  imports: [CommonModule, GN2CommonModule],
})
export class PermissionRequestInfoComponent {
  readonly STATUS_COLORS = STATUS_COLORS;
  readonly STATUS_LABELS = STATUS_LABELS;

  @Input()
  public permissionRequest: PermissionRequest | null = null;

  readonly scopeLabels: Record<PermissionRequestScope, string> = {
    [PermissionRequestScope.USER]: 'Utilisateur',
    [PermissionRequestScope.ORGANISM]: 'Organisme',
  };

  getScopeLabel(scope: PermissionRequestScope | null): string {
    if (!scope) {
      return this.scopeLabels[DEFAULT_SCOPE];
    }
    if (scope in this.scopeLabels) {
      return this.scopeLabels[scope as PermissionRequestScope];
    }
    return scope;
  }
}
