import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { AccessRequestFormComponent } from '../../components/access-request-form/access-request-form.component';
import { AccessRequestSummary } from '../../models/accessRequestSummary';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-edit.component.html',
  styleUrls: ['./access-request-edit.component.scss'],
  imports: [AccessRequestFormComponent, AccessRequestLayoutComponent],
})
export class AccessRequestEditPageComponent implements OnInit {
  accessRequestSummary: AccessRequestSummary | null = null;

  constructor(private _route: ActivatedRoute) {}

  ngOnInit() {
    this.accessRequestSummary = this._route.snapshot.data.accessRequestSummary;
    console.log(this.accessRequestSummary);
  }
}
