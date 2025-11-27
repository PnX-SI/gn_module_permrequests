import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { Router } from '@angular/router';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ConfirmationDialog } from '@geonature_common/others/modal-confirmation/confirmation.dialog';
import { ModuleService } from '@geonature/services/module.service';

import { PermissionRequest } from '../../models/permissionRequest';
import { PermissionRequestService } from '../../services/permissionRequest.service';
import {
  ValidationDescriptionDialogComponent,
  ValidationDescriptionDialogData,
} from './validation-description-dialog.component';
import { ROUTE_PATHS } from '../../gnModule.module';
@Component({
  standalone: true,
  selector: 'permission-request-toolbar',
  templateUrl: 'permission-request-toolbar.component.html',
  styleUrls: ['./permission-request-toolbar.component.scss'],
  imports: [GN2CommonModule, CommonModule, RouterModule, MatButtonModule],
})
export class PermissionRequestToolbarComponent {
  constructor(
    private _permissionRequestService: PermissionRequestService,
    private _dialog: MatDialog,
    private _moduleService: ModuleService,
    private _router: Router
  ) {}

  @Input()
  permissionRequest: PermissionRequest | null = null;

  @Input()
  withInfo: boolean = true;
  @Input()
  withEdit: boolean = true;
  @Input()
  withDelete: boolean = true;
  @Input()
  withValidate: boolean = true;

  @Output()
  deleted = new EventEmitter<number>();

  @Output()
  updated = new EventEmitter<number>();

  validationRequestPending = false;

  get currentValidationState(): 'true' | 'false' | null {
    if (this.permissionRequest?.validated === true) {
      return 'true';
    }
    if (this.permissionRequest?.validated === false) {
      return 'false';
    }
    return null;
  }

  get infoRouterLink(): string {
    if (!this.permissionRequest) {
      return '';
    }
    return `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.permissionRequest(this.permissionRequest.id_permission_request)}`;
  }

  get editRouterLink(): string {
    if (!this.permissionRequest) {
      return '';
    }
    return `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.permissionRequest(this.permissionRequest.id_permission_request)}/edit`;
  }

  deletePermissionRequest() {
    if (!this.permissionRequest) {
      return;
    }
    const message =
      "Vous vous apprétez à supprimer la requête de permission #" +
      this.permissionRequest.id_permission_request +
      '\
      Voulez-vous continuer ? \
    ';
    const dialogRef = this._dialog.open(ConfirmationDialog, {
      width: 'auto',
      // position: { top: '5%' },
      data: { message: message, yesColor: 'basic', noColor: 'warn' },
    });
    dialogRef.afterClosed().subscribe((result: any) => {
      if (result && this.permissionRequest) {
        this._permissionRequestService.deletePermissionRequest(this.permissionRequest).subscribe(() => {
          this.deleted.emit(this.permissionRequest?.id_permission_request);
        });
      }
    });
  }

  onValidationButtonClick(rawValue: 'true' | 'false'): void {
    if (!this.permissionRequest || !this.permissionRequest.cruved?.V) {
      return;
    }

    const nextValidatedValue =
      this.currentValidationState === rawValue ? null : rawValue === 'true';

    const dialogRef = this._dialog.open<
      ValidationDescriptionDialogComponent,
      ValidationDescriptionDialogData,
      string | null
    >(ValidationDescriptionDialogComponent, {
      width: '420px',
      data: {
        validated: nextValidatedValue,
        validation_description: this.permissionRequest.validation_description ?? null,
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      if (result === undefined) {
        return;
      }
      this._submitValidationRequest(nextValidatedValue, result ?? null);
    });
  }

  private _submitValidationRequest(
    validated: boolean | null,
    validation_description: string | null
  ): void {
    if (!this.permissionRequest) {
      return;
    }
    this.validationRequestPending = true;
    this._permissionRequestService
      .updateValidated(this.permissionRequest.id_permission_request, {
        validated,
        validation_description,
      })
      .subscribe({
        next: (updatedPermissionRequest: PermissionRequest) => {
          this.permissionRequest = updatedPermissionRequest;
          this.updated.emit(updatedPermissionRequest.id_permission_request);
        },
        error: () => {
          this.validationRequestPending = false;
        },
        complete: () => {
          this.validationRequestPending = false;
        },
      });
  }
}
