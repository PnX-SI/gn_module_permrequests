import { Component } from '@angular/core';
import { PermissionRequestListComponent } from '../../components/permission-request-list/permission-request-list.component';
import { ModuleLayoutComponent } from '../../layouts/module-layout/module-layout.component';

@Component({
  standalone: true,
  templateUrl: 'list.component.html',
  styleUrls: ['./list.component.scss'],
  imports: [PermissionRequestListComponent, ModuleLayoutComponent],
})
export class ListPageComponent {}
