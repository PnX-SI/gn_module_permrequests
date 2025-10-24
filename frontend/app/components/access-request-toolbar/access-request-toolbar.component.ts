import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AccessRequest } from '../../models/accessRequest';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';

@Component({
  standalone: true,
  selector: 'access-request-toolbar',
  templateUrl: 'access-request-toolbar.component.html',
  styleUrls: ['./access-request-toolbar.component.scss'],
  imports: [GN2CommonModule, CommonModule, RouterModule],
})
export class AccessRequestToolbarComponent {
  @Input()
  accessRequest!: AccessRequest;

  get infoRouterLink(): string {
    return `${this.accessRequest.id_access_request}`;
  }

  get editRouterLink(): string {
    return `${this.accessRequest.id_access_request}/edit`;
  }
}
