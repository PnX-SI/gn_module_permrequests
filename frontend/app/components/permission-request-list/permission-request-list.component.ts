import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { NgSelectModule } from '@ng-select/ng-select';
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
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { MatButtonModule } from '@angular/material/button';
import { ModuleService } from '@geonature/services/module.service';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { canCreatePermission } from '../../guards/can-create.guard';
import { STATUS, STATUS_LABELS } from '../../models/status';

type FiltersFormValue = {
  status: string[] | null;
  scope: PermissionRequestScope[] | null;
  sensitivity_filter: string[] | null;
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
  readonly PROP_INITIALIZATION_DATE = 'initialization_date';
  readonly PROP_EXPIRATION_DATE = 'expiration_date';
  readonly PROP_SCOPE = 'scope';
  readonly PROP_SENSITIVITY_FILTER = 'sensitivity_filter';
  readonly PROP_TAXA = 'taxa';
  readonly PROP_AREAS = 'areas';
  readonly PROP_VALIDATOR = 'validator.nom_complet';
  readonly PROP_VALIDATION_DESCRIPTION = 'validation_description';
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

  private readonly VALIDATED_STATUS_GROUP_LABEL = 'Validée';

  statusOptions = [
    { value: STATUS.PENDING, label: STATUS_LABELS[STATUS.PENDING] },
    { value: STATUS.IN_PROGRESS, label: STATUS_LABELS[STATUS.IN_PROGRESS] },
    { value: STATUS.REFUSED, label: STATUS_LABELS[STATUS.REFUSED] },
    {
      value: STATUS.UPCOMING,
      label: STATUS_LABELS[STATUS.UPCOMING],
      group: this.VALIDATED_STATUS_GROUP_LABEL,
    },
    {
      value: STATUS.ACTIVE,
      label: STATUS_LABELS[STATUS.ACTIVE],
      group: this.VALIDATED_STATUS_GROUP_LABEL,
    },
    {
      value: STATUS.EXPIRED,
      label: STATUS_LABELS[STATUS.EXPIRED],
      group: this.VALIDATED_STATUS_GROUP_LABEL,
    },
  ];

  scopeOptions = [
    { value: PermissionRequestScope.USER, label: 'Utilisateur' },
    { value: PermissionRequestScope.ORGANISM, label: 'Organisme' },
  ];

  sensitivityOptions = [
    { value: 'true', label: 'Oui' },
    { value: 'false', label: 'Non' },
  ];

  filtersForm = new FormGroup({
    status: new FormControl<string[] | null>([]),
    scope: new FormControl<PermissionRequestScope[] | null>([]),
    sensitivity_filter: new FormControl<string[] | null>([]),
  });

  constructor(
    private _ars: PermissionRequestService,
    private _moduleService: ModuleService,
    private _cruvedStore: CruvedStoreService
  ) {}

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
