import { Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
import { RouterModule } from '@angular/router';
import { FormControl, ReactiveFormsModule } from '@angular/forms';
import { DEFAULT_PAGINATION, PaginationItem } from '../../models/paginationItem';
import { SORT_ORDER, SortItem } from '../../models/sortItem';
import { AccessRequest } from '../../models/accessRequest';
import {
  AccessRequestListResponse,
  AccessRequestService,
} from '../../services/accessRequest.service';
import { AccessRequestToolbarComponent } from '../../components/access-request-toolbar/access-request-toolbar.component';
import { AccessRequestStatusComponent } from '../../components/access-request-status/access-request-status.component';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { MatButtonModule } from '@angular/material/button';
import { ModuleService } from '@geonature/services/module.service';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { canCreateAccess } from '../../guards/can-create-access-request.guard';

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
    AccessRequestToolbarComponent,
    AccessRequestStatusComponent,
    MatButtonModule,
  ],
})
export class AccessRequestListComponent implements OnInit, OnDestroy {
  readonly PROP_ID_ACCESS_REQUEST = 'id_access_request';
  readonly PROP_AUTHOR = 'author.nom_complet';
  readonly PROP_DESCRIPTION = 'description';
  readonly PROP_INITIALIZATION_DATE = 'initialization_date';
  readonly PROP_EXPIRATION_DATE = 'expiration_date';
  readonly PROP_TAXA = 'taxa';
  readonly PROP_VALIDATION_STATUS = 'id_validation_status';
  readonly PROP_VALIDATOR = 'validator.nom_complet';

  pagination: PaginationItem = DEFAULT_PAGINATION;
  sort: SortItem = {
    sortOrder: SORT_ORDER.DESC,
    sortBy: 'id_access_request',
  };

  accessRequests: AccessRequest[] = [];
  validationStatusControl = new FormControl<string[] | null>([]);
  readonly VALIDATION_NOMENCLATURE_TYPE = 'ACCESS_REQUEST_VALIDATION';
  canCreateAccessRequest = false;

  private _destroy$ = new Subject<void>();

  constructor(
    private _ars: AccessRequestService,
    private _moduleService: ModuleService,
    private _cruvedStore: CruvedStoreService
  ) {}

  ngOnInit() {
    this.validationStatusControl.valueChanges
      .pipe(takeUntil(this._destroy$))
      .subscribe(() => {
        this.pagination.currentPage = 1;
        this._fetchAccessRequests();
      });

    this.canCreateAccessRequest = canCreateAccess(this._cruvedStore.cruved?.[this._moduleService.currentModule.module_code])

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

  get newAccessRequestLink(): string[] {
    return [`/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.newAccessRequest}`];
  }

  private _fetchAccessRequests() {
    let params = new HttpParams();
    params = params.set('sort', this.sort.sortOrder);
    params = params.set('orderby', this.sort.sortBy);
    params = params.set('page', this.pagination.currentPage.toString());
    params = params.set('per_page', this.pagination.perPage.toString());
    const selectedValidationCodes = this.validationStatusControl.value ?? [];
    if (selectedValidationCodes.length > 0) {
      selectedValidationCodes.forEach((code) => {
        params = params.append('validation_codes', code);
      });
    }
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
