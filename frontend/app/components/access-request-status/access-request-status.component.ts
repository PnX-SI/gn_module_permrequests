import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpParams } from '@angular/common/http';
import { DEFAULT_PAGINATION, PaginationItem } from '../../models/paginationItem';
import { SORT_ORDER, SortItem } from '../../models/sortItem';
import { AccessRequest } from '../../models/accessRequest';
import {
  AccessRequestListResponse,
  AccessRequestService,
} from '../../services/accessRequest.service';
import { AccessRequestToolbarComponent } from '../access-request-toolbar/access-request-toolbar.component';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ConfigService } from '@geonature/services/config.service';

@Component({
  standalone: true,
  selector: 'access-request-status',
  templateUrl: 'access-request-status.component.html',
  styleUrls: ['./access-request-status.component.scss'],
  imports: [GN2CommonModule, CommonModule],
})
export class AccessRequestStatusComponent {
  @Input()
  accessRequest!: AccessRequest;

  constructor(
    private _config: ConfigService
  ) {}

  getValidationStatusColor(cd_nomenclature: string) {
    return this._config.ACCESS_REQUEST.VALIDATION_STATUS_INFO[cd_nomenclature]?.color;
  }
}
