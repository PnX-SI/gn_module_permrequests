import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { FormControl, FormGroup, ReactiveFormsModule } from '@angular/forms';
import { NgSelectModule } from '@ng-select/ng-select';
import { DEFAULT_PAGINATION, PaginationItem } from '../../models/paginationItem';
import { SORT_ORDER, SortItem } from '../../models/sortItem';
import { AccessRequest, AccessRequestScope, DEFAULT_SCOPE } from '../../models/accessRequest';
import {
  AccessRequestListResponse,
  AccessRequestService,
} from '../../services/accessRequest.service';
import { AccessRequestToolbarComponent } from '../../components/access-request-toolbar/access-request-toolbar.component';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { MatButtonModule } from '@angular/material/button';
import { ModuleService } from '@geonature/services/module.service';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { canCreateAccess } from '../../guards/can-create-access-request.guard';

type FiltersFormValue = {
  status: string[] | null;
  scope: AccessRequestScope[] | null;
  validated: string[] | null;
  sensitivity_filter: string[] | null;
};

@Component({
  standalone: true,
  selector: 'access-request-list',
  templateUrl: 'access-request-list.component.html',
  styleUrls: ['./access-request-list.component.scss'],
  imports: [
    GN2CommonModule,
    CommonModule,
    RouterModule,
    ReactiveFormsModule,
    NgSelectModule,
    AccessRequestToolbarComponent,
    MatButtonModule,
  ],
})
export class AccessRequestListComponent implements OnInit, OnDestroy {
  readonly PROP_ID_ACCESS_REQUEST = 'id_access_request';
  readonly PROP_AUTHOR = 'author.nom_complet';
  readonly PROP_DESCRIPTION = 'description';
  readonly PROP_INITIALIZATION_DATE = 'initialization_date';
  readonly PROP_EXPIRATION_DATE = 'expiration_date';
  readonly PROP_SCOPE = 'scope';
  readonly PROP_SENSITIVITY_FILTER = 'sensitivity_filter';
  readonly PROP_TAXA = 'taxa';
  readonly PROP_STATUS = 'status';
  readonly PROP_VALIDATOR = 'validator.nom_complet';
  readonly AccessRequestScope = AccessRequestScope;

  pagination: PaginationItem = DEFAULT_PAGINATION;
  sort: SortItem = {
    sortOrder: SORT_ORDER.DESC,
    sortBy: 'id_access_request',
  };

  accessRequests: AccessRequest[] = [];
  canCreateAccessRequest = false;

  private _destroy$ = new Subject<void>();

  readonly scopeLabels: Record<AccessRequestScope, string> = {
    [AccessRequestScope.USER]: 'Utilisateur',
    [AccessRequestScope.ORGANISM]: 'Organisme',
  };

  statusOptions = [
    { value: 'ACTIVE', label: 'Active' },
    { value: 'UPCOMING', label: 'À venir' },
    { value: 'EXPIRED', label: 'Expirée' },
    { value: 'PENDING', label: 'Non traitée' },
    { value: 'REFUSED', label: 'Refusée' },
  ];

  scopeOptions = [
    { value: AccessRequestScope.USER, label: 'Utilisateur' },
    { value: AccessRequestScope.ORGANISM, label: 'Organisme' },
  ];

  validatedOptions = [
    { value: 'true', label: 'Validée' },
    { value: 'false', label: 'Refusée' },
    { value: 'none', label: 'Non traitée' },
  ];

  sensitivityOptions = [
    { value: 'true', label: 'Oui' },
    { value: 'false', label: 'Non' },
  ];

  filtersForm = new FormGroup({
    status: new FormControl<string[] | null>([]),
    scope: new FormControl<AccessRequestScope[] | null>([]),
    validated: new FormControl<string[] | null>([]),
    sensitivity_filter: new FormControl<string[] | null>([]),
  });

  constructor(
    private _ars: AccessRequestService,
    private _moduleService: ModuleService,
    private _cruvedStore: CruvedStoreService
  ) {}

  ngOnInit() {
    this.canCreateAccessRequest = canCreateAccess(
      this._cruvedStore.cruved?.[this._moduleService.currentModule.module_code]
    );

    this.filtersForm.valueChanges.pipe(takeUntil(this._destroy$)).subscribe(() => {
      this.pagination.currentPage = 1;
      this._fetchAccessRequests();
    });

    this._fetchAccessRequests();
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

  renderScope(scope: AccessRequestScope | null): string {
    if (!scope) {
      return this.scopeLabels[DEFAULT_SCOPE];
    }
    return this.scopeLabels[scope] ?? scope;
  }

  onChangePage(event: any) {
    this.pagination.currentPage = event.offset + 1;
    this._fetchAccessRequests();
  }

  onSort(event: any) {
    this.sort = {
      sortBy: event.column.prop,
      sortOrder: event.newValue,
    };
    this._fetchAccessRequests();
  }

  onAccessRequestDeleted() {
    this._fetchAccessRequests();
  }

  onAccessRequestUpdated() {
    this._fetchAccessRequests();
  }

  get newAccessRequestLink(): string[] {
    return [`/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.newAccessRequest}`];
  }

  private _fetchAccessRequests() {
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

    const validatedFilters = new Set(filters.validated ?? []);
    validatedFilters.forEach((value) => {
      params = params.append('validated', value);
    });

    const sensitivityFilters = new Set(filters.sensitivity_filter ?? []);
    sensitivityFilters.forEach((value) => {
      params = params.append('sensitivity_filter', value);
    });

    this._ars.getAccessRequests(params).subscribe((response: AccessRequestListResponse) => {
      this.accessRequests = response.items;
      this.pagination = {
        totalItems: response.total,
        currentPage: response.page,
        perPage: response.per_page,
      };
    });
  }
}
