import { Component, Input } from '@angular/core';
import { AccessRequest } from '../../models/accessRequest';

@Component({
  standalone: true,
  selector: 'access-request-info',
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
})
export class AccessRequestInfoComponent {
  @Input()
  accessRequest: AccessRequest | null = null;
}
