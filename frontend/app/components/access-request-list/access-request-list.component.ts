import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
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
// export interface AccessRequestSummary {
//   id_access_request: number;
//   id_validation_status: number | null;
//   id_author: number;
//   id_validator: number | null;
//   expiration_date: string | null;
//   description: string | null;
//   taxa: number[];
//   permissions: number[];
// }

@Component({
  standalone: true,
  selector: 'access-request-list',
  templateUrl: 'access-request-list.component.html',
  styleUrls: ['./access-request-list.component.scss'],
  imports: [GN2CommonModule, CommonModule, AccessRequestToolbarComponent, AccessRequestStatusComponent],
})
export class AccessRequestListComponent {
  readonly PROP_ID_ACCESS_REQUEST = 'id_access_request';
  readonly PROP_AUTHOR = 'author.nom_complet';
  readonly PROP_DESCRIPTION = 'description';
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

  constructor(
    private _ars: AccessRequestService
  ) {}

  ngOnInit() {
    this._fetchAccessRequests();
  }

  renderDate(date: string): string {
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

  private _fetchAccessRequests() {
    let params = new HttpParams();
    params = params.set('sort', this.sort.sortOrder);
    params = params.set('orderby', this.sort.sortBy);
    params = params.set('page', this.pagination.currentPage.toString());
    params = params.set('per_page', this.pagination.perPage.toString());
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
