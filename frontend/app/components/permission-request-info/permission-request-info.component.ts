import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { Params, RouterModule } from '@angular/router';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';

import {
  PermissionRequest,
  PermissionRequestScope,
  DEFAULT_SCOPE,
  PermissionRequestTaxon,
  PermissionRequestArea,
} from '../../models/permissionRequest';
import { PERMISSION_REQUEST_SECTIONS } from '../permission-request-common/permission-request-sections';

const SCOPE_LABELS: Record<PermissionRequestScope, string> = {
  [PermissionRequestScope.USER]: 'Utilisateur',
  [PermissionRequestScope.ORGANISM]: 'Organisme',
};

@Component({
  standalone: true,
  selector: 'permission-request-info',
  templateUrl: 'permission-request-info.component.html',
  styleUrls: ['./permission-request-info.component.scss'],
  imports: [CommonModule, GN2CommonModule, MatCardModule, MatIconModule, MatButtonModule, RouterModule],
})
export class PermissionRequestInfoComponent {
  @Input()
  public permissionRequest: PermissionRequest | null = null;

  readonly scopeLabels = SCOPE_LABELS;
  readonly sections = PERMISSION_REQUEST_SECTIONS;
  readonly syntheseLink = ['/synthese'];

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

  get syntheseQueryParams(): Params {
    return this._computeSyntheseQueryParams(this.permissionRequest);
  }

  private _computeSyntheseQueryParams(permissionRequest: PermissionRequest | null): Params {
    const query: Params = {};
    if (!permissionRequest) {
      return query;
    }
    const uniqueCdNoms = Array.from(
      new Set(
        (permissionRequest.taxa || [])
          .map((taxon) => Number(taxon.cd_nom))
          .filter((value) => Number.isFinite(value))
      )
    ) as number[];
    if (uniqueCdNoms.length) {
      // In synthse, the query_params available is cd_ref.
      // In permission request, the taxon is referenced by cd_nom because of fk behavior.
      // But it's actually a cd_ref.
      query.cd_ref = uniqueCdNoms;
    }
    const areaParams = new Map<string, Set<number>>([
      ['COM', new Set()],
      ['DEP', new Set()],
      ['REG', new Set()],
    ]);
    (permissionRequest.areas || []).forEach((area) => {
      if (!area || !area.type_code || !areaParams.has(area.type_code)) {
        return;
      }
      if (area.id_area !== null && area.id_area !== undefined) {
        areaParams.get(area.type_code)?.add(area.id_area);
      }
    });
    areaParams.forEach((values, typeCode) => {
      if (values.size) {
        query[`area_${typeCode}`] = Array.from(values);
      }
    });
    return query;
  }
}
