import { Component, Input, OnChanges, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { MatButtonModule } from '@angular/material/button';
import { Params, RouterModule } from '@angular/router';

import { TranslateService } from '@ngx-translate/core';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { I18nService } from '@geonature/shared/translate/i18n-service';

import {
  PermissionRequest,
  PermissionRequestScope,
  DEFAULT_SCOPE,
  PermissionRequestTaxon,
  PermissionRequestArea,
} from '../../models/permissionRequest';
import { PermissionRequestService } from '../../services/permissionRequest.service';
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
  imports: [
    CommonModule,
    GN2CommonModule,
    MatCardModule,
    MatIconModule,
    MatButtonModule,
    RouterModule,
  ],
})
export class PermissionRequestInfoComponent implements OnChanges {
  @Input()
  public permissionRequest: PermissionRequest | null = null;

  readonly scopeLabels = SCOPE_LABELS;
  readonly sections = PERMISSION_REQUEST_SECTIONS;
  readonly syntheseLink = ['/synthese'];

  mapGeojson: object | null = null;

  constructor(
    private _i18nService: I18nService,
    private _translateService: TranslateService,
    private _permissionRequestService: PermissionRequestService
  ) {
    this._i18nService.initializeModuleTranslateService(this._translateService);
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['permissionRequest']) {
      this._loadMapData();
    }
  }

  private _loadMapData(): void {
    this.mapGeojson = null;
    const pr = this.permissionRequest;
    if (!pr) return;

    const hasAreas = (pr.areas?.length ?? 0) > 0;
    const hasCustomArea = !!pr.custom_area;
    if (!hasAreas && !hasCustomArea) return;

    this._permissionRequestService
      .getMapData(pr.id_permission_request)
      .subscribe({ next: (data) => { this.mapGeojson = data; } });
  }

  getCustomAreaDownloadUrl(): string | null {
    if (!this.permissionRequest?.custom_area) return null;
    return this._permissionRequestService.getCustomAreaDownloadUrl(
      this.permissionRequest.id_permission_request
    );
  }

  getScopeLabel(scope: PermissionRequestScope | null): string {
    if (!scope) return this.scopeLabels[DEFAULT_SCOPE];
    return scope in this.scopeLabels ? this.scopeLabels[scope as PermissionRequestScope] : scope;
  }

  trackByTaxon = (_: number, taxon: PermissionRequestTaxon) => taxon?.cd_nom ?? _;

  trackByArea = (_: number, area: PermissionRequestArea) => area?.id_area ?? area?.area_code ?? _;

  get syntheseQueryParams(): Params {
    return this._computeSyntheseQueryParams(this.permissionRequest);
  }

  private _computeSyntheseQueryParams(permissionRequest: PermissionRequest | null): Params {
    const query: Params = {};
    if (!permissionRequest) return query;

    const uniqueCdNoms = Array.from(
      new Set(
        (permissionRequest.taxa || [])
          .map((taxon) => Number(taxon.cd_nom))
          .filter((value) => Number.isFinite(value))
      )
    ) as number[];
    if (uniqueCdNoms.length) {
      // In synthese, the query_params available is cd_ref.
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
      if (!area || !area.type_code || !areaParams.has(area.type_code)) return;
      if (area.id_area !== null && area.id_area !== undefined) {
        areaParams.get(area.type_code)?.add(area.id_area);
      }
    });
    areaParams.forEach((values, typeCode) => {
      if (values.size) query[`area_${typeCode}`] = Array.from(values);
    });

    return query;
  }
}
