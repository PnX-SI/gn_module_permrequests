import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';

import {
  PermissionRequest,
  PermissionRequestScope,
  DEFAULT_SCOPE,
  PermissionRequestTaxon,
  PermissionRequestArea,
} from '../../models/permissionRequest';

const SCOPE_LABELS: Record<PermissionRequestScope, string> = {
  [PermissionRequestScope.USER]: 'Utilisateur',
  [PermissionRequestScope.ORGANISM]: 'Organisme',
};

@Component({
  standalone: true,
  selector: 'permission-request-info',
  templateUrl: 'permission-request-info.component.html',
  styleUrls: ['./permission-request-info.component.scss'],
  imports: [CommonModule, GN2CommonModule, MatCardModule, MatIconModule],
})
export class PermissionRequestInfoComponent {
  @Input()
  public permissionRequest: PermissionRequest | null = null;

  readonly scopeLabels = SCOPE_LABELS;

  getScopeLabel(scope: PermissionRequestScope | null): string {
    if (!scope) {
      return this.scopeLabels[DEFAULT_SCOPE];
    }
    if (scope in this.scopeLabels) {
      return this.scopeLabels[scope as PermissionRequestScope];
    }
    return scope;
  }

  trackByTaxon = (_: number, taxon: PermissionRequestTaxon) => taxon?.cd_nom ?? _;

  trackByArea = (_: number, area: PermissionRequestArea) => area?.id_area ?? area?.area_code ?? _;
}
