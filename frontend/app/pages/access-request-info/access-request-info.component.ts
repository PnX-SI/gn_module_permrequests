import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { CommonModule } from '@angular/common';

import { AccessRequestSummary } from '../../models/accessRequestSummary';
import { AccessRequestInfoComponent } from '../../components/access-request-info/access-request-info.component';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
  imports: [CommonModule, AccessRequestInfoComponent, AccessRequestLayoutComponent],
})
export class AccessRequestInfoPageComponent {
  accessRequestSummary: AccessRequestSummary | null = null;

  constructor(private _route: ActivatedRoute) {}

  ngOnInit() {
    this.accessRequestSummary = this._route.snapshot.data.accessRequestSummary;
  }
}
