import { Component } from '@angular/core';
import { AccessRequestFormComponent } from '../../components/access-request-form/access-request-form.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-new.component.html',
  styleUrls: ['./access-request-new.component.scss'],
  imports: [AccessRequestFormComponent],
})
export class AccessRequestNewPageComponent {}
