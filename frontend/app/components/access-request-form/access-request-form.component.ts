import { Component, Input } from '@angular/core';
import { AccessRequest } from '../../models/accessRequest';

@Component({
  standalone: true,
  selector: 'access-request-form',
  templateUrl: 'access-request-form.component.html',
  styleUrls: ['./access-request-form.component.scss'],
})
export class AccessRequestFormComponent {
  @Input()
  accessRequest: AccessRequest | null = null;
}
