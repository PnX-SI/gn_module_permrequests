import { Component, Input } from '@angular/core';
import { AccessRequestSummary } from '../../models/accessRequestSummary';

@Component({
  standalone: true,
  selector: 'access-request-info',
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
})
export class AccessRequestInfoComponent {
  @Input()
  accessRequestSummary: AccessRequestSummary | null = null;
}
