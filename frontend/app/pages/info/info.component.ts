import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { CommonModule } from '@angular/common';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { PermissionRequest } from '../../models/permissionRequest';
import { PermissionRequestInfoComponent } from '../../components/permission-request-info/permission-request-info.component';
import { PermissionRequestLayoutComponent } from '../../layouts/permission-request-layout/permission-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'info.component.html',
  styleUrls: ['./info.component.scss'],
  imports: [CommonModule, PermissionRequestInfoComponent, PermissionRequestLayoutComponent],
})
export class InfoPageComponent implements OnInit, OnDestroy {
  permissionRequest: PermissionRequest | null = null;

  private readonly _destroy$ = new Subject<void>();

  constructor(
    private _route: ActivatedRoute,
    private _router: Router
  ) {}

  ngOnInit(): void {
    this._route.data
      .pipe(takeUntil(this._destroy$))
      .subscribe(({ permissionRequest }: { permissionRequest: PermissionRequest | null }) => {
        this.permissionRequest = permissionRequest ?? null;
      });
  }

  ngOnDestroy(): void {
    this._destroy$.next();
    this._destroy$.complete();
  }

  onPermissionRequestUpdated(id: number): void {
    this._router.navigate([], {
      relativeTo: this._route,
      queryParams: { refresh: Date.now() },
      queryParamsHandling: 'merge',
    });
  }
}
