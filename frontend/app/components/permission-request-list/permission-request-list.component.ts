import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { RouterModule } from '@angular/router';

import { NgSelectModule } from '@ng-select/ng-select';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { Subject } from 'rxjs';
import { take, takeUntil } from 'rxjs/operators';

import { ModuleService } from '@geonature/services/module.service';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';
import { I18nService } from '@geonature/shared/translate/i18n-service';

import { DEFAULT_PAGINATION, PaginationItem } from '../../models/paginationItem';
import { SORT_ORDER, SortItem } from '../../models/sortItem';
import {
  PermissionRequest,
  PermissionRequestScope,
  DEFAULT_SCOPE,
} from '../../models/permissionRequest';
import {
  PermissionRequestListResponse,
  PermissionRequestService,
} from '../../services/permissionRequest.service';
import { PermissionRequestToolbarComponent } from '../permission-request-toolbar/permission-request-toolbar.component';
import { ROUTE_PATHS } from '../../gnModule.module';
import { canCreatePermission } from '../../guards/can-create.guard';
import { STATUS } from '../../models/status';

type FiltersFormValue = {
  status: string[] | null;
  scope: PermissionRequestScope[] | null;
  sensitivity_filter: string[] | null;
  my_validations: boolean;
};

@Component({
  standalone: true,
  selector: 'permission-request-list',
  templateUrl: 'permission-request-list.component.html',
  styleUrls: ['./permission-request-list.component.scss'],
  imports: [
    GN2CommonModule,
    CommonModule,
    RouterModule,
    ReactiveFormsModule,
    NgSelectModule,
    PermissionRequestToolbarComponent,
    MatButtonModule,
  ],
})
export class PermissionRequestListComponent implements OnInit, OnDestroy {
  readonly PROP_ID_PERMISSION_REQUEST = 'id_permission_request';
  readonly PROP_AUTHOR = 'author.nom_complet';
  readonly PROP_DESCRIPTION = 'description';
  readonly PROP_CREATED_ON = 'created_on';
  readonly PROP_EXPIRATION_DATE = 'expiration_date';
  readonly PROP_SCOPE = 'scope';
  readonly PROP_SENSITIVITY_FILTER = 'sensitivity_filter';
  readonly PROP_TAXA = 'taxa';
  readonly PROP_AREAS = 'areas';
  readonly PROP_VALIDATOR = 'validator.nom_complet';
  readonly PROP_VALIDATION_DESCRIPTION = 'validation_description';
  readonly PROP_STATUS = 'status';
  readonly PermissionRequestScope = PermissionRequestScope;

  pagination: PaginationItem = DEFAULT_PAGINATION;
  sort: SortItem = {
    sortOrder: SORT_ORDER.DESC,
    sortBy: 'id_permission_request',
  };

  permissionRequests: PermissionRequest[] = [];
  canCreatePermissionRequest = false;

  private _destroy$ = new Subject<void>();

  readonly scopeLabels: Record<PermissionRequestScope, string> = {
    [PermissionRequestScope.USER]: 'Utilisateur',
    [PermissionRequestScope.ORGANISM]: 'Organisme',
  };

  statusOptions = [
    { value: STATUS.PENDING },
    { value: STATUS.IN_PROGRESS },
    { value: STATUS.REFUSED },
    {
      value: STATUS.UPCOMING,
      group: STATUS.VALIDATED,
    },
    {
      value: STATUS.ACTIVE,
      group: STATUS.VALIDATED,
    },
    {
      value: STATUS.EXPIRED,
      group: STATUS.VALIDATED,
    },
  ];

  scopeOptions = [
    { value: PermissionRequestScope.USER },
    { value: PermissionRequestScope.ORGANISM },
  ];

  sensitivityOptions = [{ value: 'TRUE' }, { value: 'FALSE' }];

  filtersForm = new FormGroup({
    status: new FormControl<string[] | null>([]),
    scope: new FormControl<PermissionRequestScope[] | null>([]),
    sensitivity_filter: new FormControl<string[] | null>([]),
    my_validations: new FormControl<boolean>(false),
  });

  constructor(
    private _ars: PermissionRequestService,
    private _moduleService: ModuleService,
    private _cruvedStore: CruvedStoreService,
    private _i18nService: I18nService,
    private _translateService: TranslateService
  ) {
    this._i18nService.initializeModuleTranslateService(this._translateService);
  }

  ngOnInit() {
    this.canCreatePermissionRequest = canCreatePermission(
      this._cruvedStore.cruved?.[this._moduleService.currentModule.module_code]
    );

    this.filtersForm.valueChanges.pipe(takeUntil(this._destroy$)).subscribe(() => {
      this.pagination.currentPage = 1;
      this._fetchPermissionRequests();
    });

    this._fetchPermissionRequests();
  }

  ngOnDestroy(): void {
    this._destroy$.next();
    this._destroy$.complete();
  }

  renderDate(date: string | null): string {
    if (!date) {
      return '-';
    }
    return new Date(date).toLocaleDateString();
  }

  renderScope(scope: PermissionRequestScope | null): string {
    if (!scope) {
      return this.scopeLabels[DEFAULT_SCOPE];
    }
    return this.scopeLabels[scope] ?? scope;
  }

  onChangePage(event: any) {
    this.pagination.currentPage = event.offset + 1;
    this._fetchPermissionRequests();
  }

  onSort(event: any) {
    this.sort = {
      sortBy: event.column.prop,
      sortOrder: event.newValue,
    };
    this._fetchPermissionRequests();
  }

  onPermissionRequestDeleted() {
    this._fetchPermissionRequests();
  }

  onPermissionRequestUpdated() {
    this._fetchPermissionRequests();
  }

  get newPermissionRequestLink(): string[] {
    return [`/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.newPermissionRequest}`];
  }

  private _fetchPermissionRequests() {
    let params = new HttpParams();
    params = params.set('sort', this.sort.sortOrder);
    params = params.set('orderby', this.sort.sortBy);
    params = params.set('page', this.pagination.currentPage.toString());
    params = params.set('per_page', this.pagination.perPage.toString());
    const filters = this.filtersForm.value as FiltersFormValue;
    const statusFilters = new Set(filters.status ?? []);
    statusFilters.forEach((value) => {
      params = params.append('status', value);
    });

    const scopeFilters = new Set(filters.scope ?? []);
    scopeFilters.forEach((value) => {
      params = params.append('scope', value);
    });

    const sensitivityFilters = new Set(filters.sensitivity_filter ?? []);
    sensitivityFilters.forEach((value) => {
      params = params.append('sensitivity_filter', value);
    });

    if (filters.my_validations) {
      params = params.append('my_validations', 'true');
    }

    this._ars.getPermissionRequests(params).subscribe((response: PermissionRequestListResponse) => {
      this.permissionRequests = response.items;
      this.pagination = {
        totalItems: response.total,
        currentPage: response.page,
        perPage: response.per_page,
      };
    });
  }
}
