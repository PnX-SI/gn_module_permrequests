import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { AccessRequestFormComponent } from '../../components/access-request-form/access-request-form.component';
import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-edit.component.html',
  styleUrls: ['./access-request-edit.component.scss'],
  imports: [CommonModule, AccessRequestFormComponent, AccessRequestLayoutComponent],
})
export class AccessRequestEditPageComponent implements OnInit, OnDestroy {
  accessRequest: AccessRequest | null = null;

  private readonly _destroy$ = new Subject<void>();

  constructor(private _route: ActivatedRoute, private _router: Router) {}

  ngOnInit() {
    this._route.data
      .pipe(takeUntil(this._destroy$))
      .subscribe(({ accessRequest }: { accessRequest: AccessRequest }) => {
        this.accessRequest = accessRequest ?? null;
      });
  }

  ngOnDestroy(): void {
    this._destroy$.next();
    this._destroy$.complete();
  }

  onAccessRequestUpdated(id: number): void {
    this._router.navigate([], {
      relativeTo: this._route,
      queryParams: { refresh: Date.now() },
      queryParamsHandling: 'merge',
    });
  }
}
