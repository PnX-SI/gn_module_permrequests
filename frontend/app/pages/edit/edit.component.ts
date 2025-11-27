import { CommonModule } from '@angular/common';
import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

import { PermissionRequestFormComponent } from '../../components/permission-request-form/permission-request-form.component';
import { PermissionRequest } from '../../models/permissionRequest';
import { PermissionRequestLayoutComponent } from '../../layouts/permission-request-layout/permission-request-layout.component';

@Component({
  standalone: true,
  templateUrl: 'edit.component.html',
  styleUrls: ['./edit.component.scss'],
  imports: [CommonModule, PermissionRequestFormComponent, PermissionRequestLayoutComponent],
})
export class EditPageComponent implements OnInit, OnDestroy {
  permissionRequest: PermissionRequest | null = null;

  private readonly _destroy$ = new Subject<void>();

  constructor(
    private _route: ActivatedRoute,
    private _router: Router
  ) {}

  ngOnInit() {
    this._route.data
      .pipe(takeUntil(this._destroy$))
      .subscribe(({ permissionRequest }: { permissionRequest: PermissionRequest }) => {
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
