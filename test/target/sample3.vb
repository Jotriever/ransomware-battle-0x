Private Sub Command1_Click()
Dim N, D  As  Single
Dim tag As String

N = Val(TxtNumber.Text)

Select Case N
Case Is < 2
Lbl_Answer.Caption = "It is not a prime number"

Case Is = 2
Lbl_Answer.Caption = "It is a prime number"

Case Is > 2
D = 2
Do
If N / D = Int(N / D) Then
Lbl_Answer.Caption = "It is not a prime number"
tag = "Not Prime"
Exit Do
End If
D = D + 1

Loop While D <= N - 1
If tag <> "Not Prime" Then
Lbl_Answer.Caption = "It is a prime number"
End If
End Select
End Sub