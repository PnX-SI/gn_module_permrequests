import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';


import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ConfirmationDialog } from '@geonature_common/others/modal-confirmation/confirmation.dialog';
import { ModuleService } from '@geonature/services/module.service';

import { PermissionRequest } from '../../models/permissionRequest';
import { PermissionRequestService } from '../../services/permissionRequest.service';
import { ROUTE_PATHS } from '../../gnModule.module';
import { STATUS_LABELS } from '../../models/status';
import { ValidationDescriptionDialogComponent, ValidationDescriptionDialogData, ValidationDescriptionDialogResult } from './validation-description-dialog.component';
@Component({
  standalone: true,
  selector: 'permission-request-toolbar',
  templateUrl: 'permission-request-toolbar.component.html',
  styleUrls: ['./permission-request-toolbar.component.scss'],
  imports: [GN2CommonModule, CommonModule, RouterModule, MatButtonModule],
})
export class PermissionRequestToolbarComponent {
  readonly STATUS_LABELS = STATUS_LABELS;

  constructor(
    private _permissionRequestService: PermissionRequestService,
    private _dialog: MatDialog,
    private _moduleService: ModuleService,
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


  validationRequestPending = false;

  get validationButtonIcon(): string {
    if (this.permissionRequest?.validated === true) {
      return 'check-circle';
    }
    if (this.permissionRequest?.validated === false) {
      return 'cancel';
    }
    return 'edit';
  }

  get validationButtonLabel(): string {
    if (this.permissionRequest?.validated === true) {
      return 'Validée';
    }
    if (this.permissionRequest?.validated === false) {
      return 'Refusée';
    }
    return 'Gérer la validation';
  }

  openValidationDialog(): void {
    if (!this.permissionRequest || !this.permissionRequest.cruved?.V) {
      return;
    }

    const dialogRef = this._dialog.open<
      ValidationDescriptionDialogComponent,
      ValidationDescriptionDialogData,
      ValidationDescriptionDialogResult | undefined
    >(ValidationDescriptionDialogComponent, {
      width: '500px',
      data: {
        validated: this.permissionRequest.validated ?? null,
        validation_description: this.permissionRequest.validation_description ?? null,
        initialization_date: this.permissionRequest.initialization_date ?? null,
        expiration_date: this.permissionRequest.expiration_date ?? null,
      },
    });

    dialogRef.afterClosed().subscribe((result) => {
      if (!result) {
        return;
      }
      this._submitValidationRequest(result.validated, result.validation_description);
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
