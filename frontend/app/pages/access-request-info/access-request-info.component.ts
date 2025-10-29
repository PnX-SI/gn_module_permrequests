import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestInfoComponent } from '../../components/access-request-info/access-request-info.component';
import { AccessRequestLayoutComponent } from '../../layouts/access-request-layout/access-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'access-request-info.component.html',
  styleUrls: ['./access-request-info.component.scss'],
  imports: [CommonModule, AccessRequestInfoComponent, AccessRequestLayoutComponent],
})
export class AccessRequestInfoPageComponent implements OnInit, OnDestroy {
  accessRequest: AccessRequest | null = null;

  private readonly _destroy$ = new Subject<void>();

  constructor(
    private _route: ActivatedRoute,
    private _router: Router,
  ) {}

  ngOnInit(): void {
    this._route.data
      .pipe(takeUntil(this._destroy$))
      .subscribe(({ accessRequest }: { accessRequest: AccessRequest | null }) => {
        this.accessRequest = accessRequest ?? null;
      });
  }

  ngOnDestroy(): void {
    this._destroy$.next();
    this._destroy$.complete();
  }

  onAccessRequestUpdated(id: number): void {
    console.log("-- hop hop hop");
    this._router.navigate([], {
      relativeTo: this._route,
      queryParams: { refresh: Date.now() },
      queryParamsHandling: 'merge',
    });
  }
}
