import { Component } from '@angular/core';
import { AccessRequestListComponent } from '../../components/access-request-list/access-request-list.component';
import { ModuleLayoutComponent } from '../../layouts/module-layout/module-layout.component';

@Component({
  standalone: true,
  templateUrl: 'list.component.html',
  styleUrls: ['./list.component.scss'],
  providers: [],
  imports: [AccessRequestListComponent, ModuleLayoutComponent],
})
export class ListPageComponent {}
