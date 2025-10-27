import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ModuleService } from '@geonature/services/module.service';

import { AccessRequest } from '../../models/accessRequest';
import { ModuleLayoutComponent } from '../module-layout/module-layout.component';
import { AccessRequestStatusComponent } from '../../components/access-request-status/access-request-status.component';
import { AccessRequestToolbarComponent } from '../../components/access-request-toolbar/access-request-toolbar.component';

@Component({
  standalone: true,
  selector: 'access-request-layout',
  templateUrl: 'access-request-layout.component.html',
  styleUrls: ['access-request-layout.component.scss'],
  imports: [
    GN2CommonModule,
    RouterModule,
    CommonModule,
    ModuleLayoutComponent,
    AccessRequestStatusComponent,
    AccessRequestToolbarComponent,
  ],
})
export class AccessRequestLayoutComponent {
  get homeRouterLink(): string {
    return `/${this._modules.currentModule.module_url}`;
  }

  @Input()
  accessRequest!: AccessRequest;

  @Input()
  withInfo: boolean = true;
  @Input()
  withEdit: boolean = true;
  @Input()
  withDelete: boolean = true;

  constructor(private _modules: ModuleService) {}
}
