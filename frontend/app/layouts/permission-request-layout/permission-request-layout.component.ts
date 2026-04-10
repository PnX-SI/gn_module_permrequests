import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ModuleService } from '@geonature/services/module.service';

import { PermissionRequest } from '../../models/permissionRequest';
import { ModuleLayoutComponent } from '../module-layout/module-layout.component';
import { PermissionRequestToolbarComponent } from '../../components/permission-request-toolbar/permission-request-toolbar.component';

@Component({
  standalone: true,
  selector: 'permission-request-layout',
  templateUrl: 'permission-request-layout.component.html',
  styleUrls: ['permission-request-layout.component.scss'],
  imports: [
    GN2CommonModule,
    RouterModule,
    CommonModule,
    ModuleLayoutComponent,
    PermissionRequestToolbarComponent,
  ],
})
export class PermissionRequestLayoutComponent {
  get homeRouterLink(): string {
    return `/${this._modules.currentModule.module_url}`;
  }

  @Input()
  permissionRequest: PermissionRequest | null = null;

  @Input()
  withInfo: boolean = true;
  @Input()
  withEdit: boolean = true;
  @Input()
  withDelete: boolean = true;
  @Input()
  withValidate: boolean = true;

  @Output()
  updated = new EventEmitter<number>();

  onPermissionRequestUpdated(accesRequestId: number) {
    this.updated.emit(accesRequestId);
  }

  onPermissionRequestDeleted(accesRequestId: number) {
    this._router.navigate([this.homeRouterLink]);
  }

  constructor(
    private _modules: ModuleService,
    private _router: Router
  ) {}
}
