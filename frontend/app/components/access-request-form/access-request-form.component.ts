import { Component, Input } from '@angular/core';
import { AccessRequestSummary } from '../../models/accessRequestSummary';

@Component({
  standalone: true,
  selector: 'access-request-form',
  templateUrl: 'access-request-form.component.html',
  styleUrls: ['./access-request-form.component.scss'],
})
export class AccessRequestFormComponent {
  @Input()
  accessRequestSummary: AccessRequestSummary | null = null;
}
