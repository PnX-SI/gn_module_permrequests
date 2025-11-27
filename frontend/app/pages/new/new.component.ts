import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

import { PermissionRequestFormComponent } from '../../components/permission-request-form/permission-request-form.component';
import { PermissionRequestLayoutComponent } from '../../layouts/permission-request-layout/permission-request-layout.component';
@Component({
  standalone: true,
  templateUrl: 'new.component.html',
  styleUrls: ['./new.component.scss'],
  imports: [CommonModule, PermissionRequestFormComponent, PermissionRequestLayoutComponent],
})
export class NewPageComponent {}
