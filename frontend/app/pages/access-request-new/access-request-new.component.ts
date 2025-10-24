import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

import { AccessRequestFormComponent } from '../../components/access-request-form/access-request-form.component';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';
@Component({
  standalone: true,
  templateUrl: 'access-request-new.component.html',
  styleUrls: ['./access-request-new.component.scss'],
  imports: [CommonModule, AccessRequestFormComponent, AccessRequestLayoutComponent],
})
export class AccessRequestNewPageComponent {}
