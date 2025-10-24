import { CommonModule } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { AccessRequestFormComponent } from '../../components/access-request-form/access-request-form.component';
import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-edit.component.html',
  styleUrls: ['./access-request-edit.component.scss'],
  imports: [CommonModule, AccessRequestFormComponent, AccessRequestLayoutComponent],
})
export class AccessRequestEditPageComponent implements OnInit {
  accessRequest: AccessRequest | null = null;
  constructor(private _route: ActivatedRoute) {}

  ngOnInit() {
    this.accessRequest = this._route.snapshot.data['accessRequest'];
  }
}
