import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { AccessRequestSummary } from '../../models/accessRequestSummary';
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
  accessRequestSummary!: AccessRequestSummary;

  get infoRouterLink(): string {
    return `${this.accessRequestSummary.id_access_request}`;
  }

  get editRouterLink(): string {
    return `${this.accessRequestSummary.id_access_request}/edit`;
  }
}
