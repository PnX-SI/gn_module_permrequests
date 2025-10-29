import { Component, Input, OnDestroy, OnInit, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';

import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { AccessRequest } from '../../models/accessRequest';

@Component({
  standalone: true,
  selector: 'access-request-info',
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
  imports: [CommonModule]
})
export class AccessRequestInfoComponent {

  @Input()
  public accessRequest: AccessRequest | null = null;
}
